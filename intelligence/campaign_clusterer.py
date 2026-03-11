"""
intelligence/campaign_clusterer.py — Juwan CTI v3.0
MinHash/LSH + NetworkX campaign fingerprinting engine.
Runs as a Celery periodic task every 15 minutes.

Algorithm:
  1. Pull last 24h IOC events from PostgreSQL
  2. Build 3-gram shingles on raw_input text
  3. MinHash (128 permutations) per document
  4. LSH clustering (threshold=0.5) → candidate pairs
  5. NetworkX graph — dense subgraphs (degree > 3) → active campaign
  6. Write campaign records + update event FK
"""
from datetime import datetime, timezone
from config import settings
from logger import get_logger

logger = get_logger(__name__)


# ─── Shingling & MinHash ──────────────────────────────────────────────

def _shingles(text: str, k: int = 3) -> set:
    """Generate k-gram character shingles."""
    text = text.lower().strip()
    if len(text) < k:
        return {text}
    return {text[i:i+k] for i in range(len(text) - k + 1)}


def _build_minhash(text: str, num_perm: int = 128):
    """Build a MinHash object for the given text."""
    try:
        from datasketch import MinHash
        m = MinHash(num_perm=num_perm)
        for shingle in _shingles(text):
            m.update(shingle.encode("utf-8"))
        return m
    except ImportError:
        logger.warning("datasketch not installed — campaign clustering unavailable")
        return None


# ─── Clustering ───────────────────────────────────────────────────────

def _cluster_events(events: list) -> dict[str, list]:
    """
    Cluster IOC events using MinHash LSH.

    Returns:
        dict mapping cluster_id -> list of event IDs
    """
    if not events:
        return {}

    try:
        from datasketch import MinHashLSH
        import networkx as nx

        num_perm  = settings.CAMPAIGN_MINHASH_PERMS
        threshold = settings.CAMPAIGN_LSH_THRESHOLD

        lsh = MinHashLSH(threshold=threshold, num_perm=num_perm)
        minhashes = {}

        for event in events:
            text = (event.raw_input or "") + " ".join(event.indicators or [])
            if len(text.strip()) < 5:
                continue
            m = _build_minhash(text, num_perm)
            if m is None:
                return {}
            try:
                lsh.insert(event.id, m)
                minhashes[event.id] = m
            except Exception:
                pass

        # Build similarity graph
        G = nx.Graph()
        G.add_nodes_from(minhashes.keys())

        for eid, m in minhashes.items():
            neighbors = lsh.query(m)
            for n in neighbors:
                if n != eid:
                    G.add_edge(eid, n)

        # Dense subgraphs = campaigns (degree > 3 or just connected components with >2 nodes)
        campaigns = {}
        for i, component in enumerate(nx.connected_components(G)):
            if len(component) >= 2:
                cluster_id = f"cluster-{i}"
                campaigns[cluster_id] = list(component)

        logger.debug(f"Campaign clusterer: {len(events)} events → {len(campaigns)} clusters")
        return campaigns

    except ImportError:
        logger.warning("networkx or datasketch not installed")
        return {}
    except Exception as e:
        logger.error(f"Clustering failed: {e}", exc_info=True)
        return {}


# ─── Campaign Writer ──────────────────────────────────────────────────

def _write_campaign(session, cluster_events: list, cluster_id: str) -> str:
    """Persist a campaign record and link its IOC events."""
    from intelligence.ioc_store import Campaign, IOCEvent

    timestamps = [e.timestamp for e in cluster_events if e.timestamp]
    channels   = list({e.channel for e in cluster_events})
    from utils.ensemble import TTP_MAP  # reuse TTP mapping
    ttps = list({TTP_MAP.get(ch, "T1566.001") for ch in channels})

    campaign = Campaign(
        name=f"Campaign-{cluster_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}",
        first_seen=min(timestamps) if timestamps else datetime.now(timezone.utc),
        last_seen=max(timestamps) if timestamps else datetime.now(timezone.utc),
        victim_count=len(cluster_events),
        channels=channels,
        ttps=ttps,
    )
    session.add(campaign)
    session.flush()

    for event in cluster_events:
        event.campaign_id = campaign.id

    session.commit()
    logger.info(f"Campaign written: {campaign.id} [{campaign.name}] — {len(cluster_events)} events")
    return campaign.id


# ─── Main Cluster Run ─────────────────────────────────────────────────

def run_campaign_clustering():
    """
    Full clustering pipeline — called by Celery beat every 15 min.
    Safe to call manually for testing.
    """
    logger.debug("Campaign clustering started")
    try:
        from intelligence.ioc_store import get_recent_ioc_events, get_session, IOCEvent

        events = get_recent_ioc_events(hours=settings.CAMPAIGN_LOOKBACK_HOURS)
        if not events:
            logger.debug("No recent IOC events to cluster")
            return

        # Only cluster uncampaigned events
        unclustered = [e for e in events if not e.campaign_id]
        if not unclustered:
            logger.debug("All events already assigned to campaigns")
            return

        clusters = _cluster_events(unclustered)

        if not clusters:
            logger.debug("No clusters found")
            return

        with get_session() as session:
            event_map = {e.id: e for e in unclustered}
            for cluster_id, event_ids in clusters.items():
                cluster_events = [event_map[eid] for eid in event_ids if eid in event_map]
                if cluster_events:
                    _write_campaign(session, cluster_events, cluster_id)

        logger.info(f"Campaign clustering complete: {len(clusters)} campaigns written")

    except Exception as e:
        logger.error(f"Campaign clustering error: {e}", exc_info=True)


# ─── Celery Integration ───────────────────────────────────────────────

try:
    from celery import Celery
    from celery.schedules import crontab

    celery_app = Celery("cti_v3", broker=settings.REDIS_URL)

    celery_app.conf.beat_schedule = {
        "cluster-campaigns": {
            "task": "intelligence.campaign_clusterer.run_clustering_task",
            "schedule": settings.CAMPAIGN_CLUSTER_INTERVAL,  # seconds
        },
        "scrape-osint-feeds": {
            "task": "intelligence.campaign_clusterer.run_osint_scraper_task",
            "schedule": 900.0, # Run every 15 minutes (900 seconds)
        }
    }
    celery_app.conf.timezone = "UTC"

    @celery_app.task(name="intelligence.campaign_clusterer.run_clustering_task")
    def run_clustering_task():
        run_campaign_clustering()
        
    @celery_app.task(name="intelligence.campaign_clusterer.run_osint_scraper_task")
    def run_osint_scraper_task():
        from intelligence.osint_scraper import run_osint_pipeline
        run_osint_pipeline()

except ImportError:
    logger.debug("Celery not installed — campaign clustering runs manually only")

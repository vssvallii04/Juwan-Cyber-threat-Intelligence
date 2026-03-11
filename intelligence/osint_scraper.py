import re
import uuid
import time
from typing import List, Dict, Any

try:
    import feedparser
except ImportError:
    feedparser = None

from logger import get_logger

logger = get_logger(__name__)

# Mock Telegram Channels (actually using public RSS feeds of Telegram web viewers for OSINT)
OSINT_FEEDS = [
    "https://rsshub.app/telegram/channel/ransomware_news",
    "https://rsshub.app/telegram/channel/vxunderground",
    "https://rsshub.app/telegram/channel/MalwareHunterTeam",
    # Note: RSSHub is a public aggregator. In production, use official Telegram MTProto APIs.
]

# IOC Extraction Regexes
IOC_REGEX = {
    "ipv4": re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b"),
    "sha256": re.compile(r"\b[A-Fa-f0-9]{64}\b"),
    "md5": re.compile(r"\b[A-Fa-f0-9]{32}\b"),
    "email": re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b"),
    "url": re.compile(r"https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+"),
    "btc_address": re.compile(r"\b(?:1|3|bc1)[a-zA-HJ-NP-Z0-9]{25,39}\b")
}

def extract_iocs(text: str) -> List[str]:
    """Extract actionable Indicators of Compromise from raw text."""
    indicators = set()
    if not text:
        return list(indicators)
        
    for ioc_type, pattern in IOC_REGEX.items():
        matches = pattern.findall(text)
        for match in matches:
            indicators.add(match)
            
    return list(indicators)

def scrape_feeds() -> List[Dict[str, Any]]:
    """
    Fetch posts from public OSINT feeds (e.g. Telegram via RSSBridge),
    extract IOCs, and format them for the Campaign Clusterer.
    """
    if not feedparser:
        logger.error("feedparser is not installed. Cannot scrape OSINT feeds.")
        return []

    logger.info("Starting Dark Web / Telegram OSINT Scraper...")
    scraped_events = []
    
    for feed_url in OSINT_FEEDS:
        try:
            feed = feedparser.parse(feed_url)
            if feed.bozo:
                continue # Feed parsing error
                
            for entry in feed.entries[:10]: # Process latest 10 posts per feed
                text = f"{entry.get('title', '')} {entry.get('description', '')}"
                iocs = extract_iocs(text)
                
                if not iocs:
                    continue # Ignore chatter without actionable intel
                
                # We format this exactly like a standard CTI request to feed into the clusterer
                # Assume OSINT feeds have a high baseline confidence of being threat-related
                event = {
                    "artifact_id": str(uuid.uuid4()),
                    "channel": "osint",
                    "confidence": 0.85, 
                    "threat_level": "HIGH",
                    "indicators": iocs,
                    "indicator_weights": {ioc: 0.85 for ioc in iocs},
                    "raw_data": text[:500] # Store snippet
                }
                scraped_events.append(event)
                
        except Exception as e:
            logger.error(f"Failed to scrape feed {feed_url}: {e}")
            
    logger.info(f"OSINT Scraper finished. Extracted {len(scraped_events)} new actionable intelligence events.")
    return scraped_events

def run_osint_pipeline():
    """
    Entrypoint for the periodic Celery task or Cron job.
    Scrapes feeds and dumps them directly into the Postgres IOC store.
    """
    events = scrape_feeds()
    if not events:
        return
        
    try:
        from intelligence.ioc_store import log_ioc_event
        count = 0
        for ev in events:
            log_ioc_event(
                artifact_id=ev["artifact_id"],
                channel=ev["channel"],
                confidence=ev["confidence"],
                prediction=ev["threat_level"],
                indicators=ev["indicators"],
                weights=ev["indicator_weights"],
                raw=ev["raw_data"]
            )
            count += 1
        logger.info(f"Saved {count} OSINT events to database for campaign clustering.")
    except Exception as e:
        logger.error(f"Failed to save OSINT events to DB: {e}")

if __name__ == "__main__":
    import json
    # Test execution
    res = scrape_feeds()
    print(json.dumps(res, indent=2))

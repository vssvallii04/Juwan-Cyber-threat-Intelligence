"""
intelligence/taxii_server.py — Juwan CTI v3.0
TAXII 2.1 collection endpoint backed by PostgreSQL IOC store.
Compatible with: MISP, OpenCTI, Anomali STAXX

Endpoints (mounted at /taxii/):
  GET  /taxii/                          → TAXII discovery
  GET  /taxii/api-root/                 → API root info
  GET  /taxii/api-root/collections/     → list collections
  GET  /taxii/api-root/collections/{id}/objects/ → serve IOC STIX objects

Mounted into the main app in app.py:
  app.mount("/taxii", taxii_router)
"""
from fastapi import APIRouter, Request
from fastapi.responses import JSONResponse
from datetime import datetime, timezone
from logger import get_logger

logger = get_logger(__name__)

taxii_router = APIRouter()

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"
STIX_CONTENT_TYPE  = "application/stix+json;version=2.1"

COLLECTION_ID = "cti-v3-ioc-store"
COLLECTION_TITLE = "Juwan CTI v3.0 IOC Store"


def _taxii_response(content: dict, status: int = 200):
    return JSONResponse(
        content=content,
        status_code=status,
        headers={"Content-Type": TAXII_CONTENT_TYPE},
    )


# ─── Discovery ────────────────────────────────────────────────────────

@taxii_router.get("/", summary="TAXII 2.1 Discovery")
def taxii_discovery(request: Request):
    """
    TAXII 2.1 Server Discovery endpoint.
    Returns available API roots.
    """
    base = str(request.base_url).rstrip("/")
    return _taxii_response({
        "title": "Juwan CTI v3.0 TAXII Server",
        "description": "Multi-modal Cyber Threat Intelligence TAXII 2.1 endpoint",
        "contact": "vssvallii04@github",
        "api_roots": [f"{base}/taxii/api-root/"],
        "default": f"{base}/taxii/api-root/",
    })


# ─── API Root ─────────────────────────────────────────────────────────

@taxii_router.get("/api-root/", summary="TAXII API Root")
def taxii_api_root(request: Request):
    """TAXII 2.1 API Root information."""
    base = str(request.base_url).rstrip("/")
    return _taxii_response({
        "title": "Juwan CTI v3.0 API Root",
        "description": "IOC intelligence from email, URL, chat, voice, and image analysis",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 10485760,
        "collections_endpoint": f"{base}/taxii/api-root/collections/",
    })


# ─── Collections ──────────────────────────────────────────────────────

@taxii_router.get("/api-root/collections/", summary="TAXII Collections")
def taxii_collections():
    """List available TAXII 2.1 collections."""
    return _taxii_response({
        "collections": [
            {
                "id": COLLECTION_ID,
                "title": COLLECTION_TITLE,
                "description": "IOC events from Juwan CTI v3.0 multi-modal analysis",
                "can_read": True,
                "can_write": False,
                "media_types": [STIX_CONTENT_TYPE],
            }
        ]
    })


@taxii_router.get("/api-root/collections/{collection_id}/", summary="Collection Info")
def taxii_collection_info(collection_id: str):
    """Get details for a specific collection."""
    if collection_id != COLLECTION_ID:
        return _taxii_response({"title": "Not Found"}, status=404)
    return _taxii_response({
        "id": COLLECTION_ID,
        "title": COLLECTION_TITLE,
        "description": "IOC events from Juwan CTI v3.0 multi-modal analysis",
        "can_read": True,
        "can_write": False,
        "media_types": [STIX_CONTENT_TYPE],
    })


# ─── Objects (IOC → STIX) ─────────────────────────────────────────────

@taxii_router.get(
    "/api-root/collections/{collection_id}/objects/",
    summary="TAXII Collection Objects"
)
def taxii_objects(
    collection_id: str,
    limit: int = 100,
    added_after: str = None,
):
    """
    Serve IOC events as STIX 2.1 Indicator objects.
    Supports: limit, added_after (ISO 8601) query params.
    """
    if collection_id != COLLECTION_ID:
        return _taxii_response({"title": "Not Found"}, status=404)

    try:
        from intelligence.ioc_store import get_session, IOCEvent
        from datetime import timedelta

        with get_session() as session:
            query = session.query(IOCEvent).order_by(IOCEvent.timestamp.desc())

            if added_after:
                try:
                    cutoff = datetime.fromisoformat(added_after.replace("Z", "+00:00"))
                    query = query.filter(IOCEvent.timestamp > cutoff)
                except ValueError:
                    pass

            events = query.limit(min(limit, 1000)).all()

        stix_objects = []
        for event in events:
            stix_objects.append(_event_to_stix_indicator(event))

        return JSONResponse(
            content={
                "type": "bundle",
                "id": f"bundle--taxii-{COLLECTION_ID}",
                "spec_version": "2.1",
                "objects": stix_objects,
            },
            headers={"Content-Type": STIX_CONTENT_TYPE},
        )

    except Exception as e:
        logger.error(f"TAXII objects error: {e}", exc_info=True)
        return _taxii_response({"title": "Internal Server Error"}, status=500)


# ─── Status endpoint ──────────────────────────────────────────────────

@taxii_router.get("/api-root/status/", summary="TAXII Server Status")
def taxii_status():
    """TAXII server health status."""
    return _taxii_response({
        "id": "juwan-cti-v3-taxii",
        "status": "operational",
        "request_timestamp": datetime.now(timezone.utc).isoformat(),
        "successes": [],
        "failures": [],
        "pendings": [],
    })


# ─── STIX Conversion Helper ───────────────────────────────────────────

TTP_MAP = {
    "email":    "T1566.001",
    "url":      "T1566.002",
    "url_apk":  "T1476",
    "chat":     "T1566.003",
    "voice":    "T1598.004",
    "image":    "T1566.004",
    "ensemble": "T1566.001",
}


def _event_to_stix_indicator(event) -> dict:
    """Convert an IOCEvent ORM object to a STIX 2.1 Indicator dict."""
    ts = str(event.timestamp).replace(" ", "T") + "Z" if event.timestamp else datetime.now(timezone.utc).isoformat()
    raw = (event.raw_input or "")[:200].replace("'", "\\'")
    channel = event.channel or "unknown"

    pattern = (
        f"[url:value = '{raw}']" if channel in ("url", "url_apk")
        else "[email-message:subject LIKE '%phishing%']" if channel == "email"
        else "[network-traffic:dst_port = 443]"
    )

    return {
        "type": "indicator",
        "spec_version": "2.1",
        "id": f"indicator--{event.id}",
        "name": f"IOC-{channel}-{event.id[:8]}",
        "description": f"Detected by {channel} module. Threat: {event.threat_level}. Confidence: {event.confidence}",
        "pattern": pattern,
        "pattern_type": "stix",
        "valid_from": ts,
        "labels": ["malicious-activity"],
        "indicator_types": ["malicious-activity"],
        "confidence": int(event.confidence * 100),
        "extensions": {
            "x-juwan-cti": {
                "channel": channel,
                "threat_level": event.threat_level,
                "indicators": event.indicators or [],
                "mitre_ttp": TTP_MAP.get(channel, "T1566.001"),
                "campaign_id": event.campaign_id,
            }
        },
    }

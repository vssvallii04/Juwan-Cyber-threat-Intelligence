"""
intelligence/stix_exporter.py — Juwan CTI v3.0
STIX 2.1 bundle export for campaigns with MITRE ATT&CK TTP mapping
"""
from datetime import datetime, timezone
from logger import get_logger

logger = get_logger(__name__)

# MITRE ATT&CK TTP mapping per channel
TTP_MAP = {
    "email":    "T1566.001",  # Spearphishing Attachment
    "url":      "T1566.002",  # Spearphishing Link
    "url_apk":  "T1476",      # Deliver Malicious App via App Store
    "chat":     "T1566.003",  # Spearphishing via Service
    "voice":    "T1598.004",  # Spearphishing Voice
    "image":    "T1566.004",  # Spearphishing via Image
    "ensemble": "T1566.001",
}


def export_campaign_as_stix(campaign_id: str) -> dict:
    """
    Generate a STIX 2.1 Bundle for a campaign.

    Args:
        campaign_id: ID of the campaign from PostgreSQL

    Returns:
        STIX 2.1 Bundle dict (JSON-serialisable)
    """
    try:
        from intelligence.ioc_store import get_session, Campaign, IOCEvent

        with get_session() as session:
            campaign = session.query(Campaign).filter_by(id=campaign_id).first()
            if not campaign:
                return {"error": f"Campaign {campaign_id!r} not found"}

            events = (
                session.query(IOCEvent)
                .filter_by(campaign_id=campaign_id)
                .order_by(IOCEvent.timestamp.asc())
                .all()
            )

        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Collect TTPs from event channels
        ttps = list({TTP_MAP.get(e.channel, "T1566.001") for e in events})

        # BUILD STIX 2.1 OBJECTS ──────────────────────────────────────

        campaign_obj = {
            "type": "campaign",
            "spec_version": "2.1",
            "id": f"campaign--{campaign_id}",
            "name": campaign.name or f"CTI-Campaign-{campaign_id[:8]}",
            "first_seen": str(campaign.first_seen).replace(" ", "T") + "Z" if campaign.first_seen else now,
            "last_seen":  str(campaign.last_seen).replace(" ", "T") + "Z" if campaign.last_seen else now,
            "description": f"Detected by Juwan CTI v3.0. Channels: {', '.join(campaign.channels or [])}",
        }

        threat_actor_obj = {
            "type": "threat-actor",
            "spec_version": "2.1",
            "id": f"threat-actor--{campaign_id}",
            "name": f"Actor-{campaign_id[:8]}",
            "description": "Unknown threat actor attributed to this campaign by Juwan CTI v3.0",
            "threat_actor_types": ["criminal"],
            "sophistication": "intermediate",
            "resource_level": "individual",
        }

        indicator_objects = []
        relationship_objects = []

        for event in events[:50]:  # cap at 50 IOCs per bundle
            ioc_id = f"indicator--{event.id}"
            pattern = _build_stix_pattern(event)

            indicator_obj = {
                "type": "indicator",
                "spec_version": "2.1",
                "id": ioc_id,
                "name": f"IOC-{event.channel}-{event.id[:8]}",
                "description": f"Detected by {event.channel} module. Confidence: {event.confidence}",
                "pattern": pattern,
                "pattern_type": "stix",
                "valid_from": str(event.timestamp).replace(" ", "T") + "Z",
                "labels": ["malicious-activity"],
                "indicator_types": ["malicious-activity"],
                "confidence": int(event.confidence * 100),
                "extensions": {
                    "x-juwan-cti": {
                        "channel": event.channel,
                        "threat_level": event.threat_level,
                        "indicators": event.indicators or [],
                        "mitre_ttp": TTP_MAP.get(event.channel, "T1566.001"),
                    }
                },
            }
            indicator_objects.append(indicator_obj)

            # Relationship: indicator indicates campaign
            relationship_objects.append({
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{event.id}",
                "relationship_type": "indicates",
                "source_ref": ioc_id,
                "target_ref": f"campaign--{campaign_id}",
                "created": now,
                "modified": now,
            })

        # Attack pattern objects for TTPs
        attack_patterns = []
        for ttp in ttps:
            attack_patterns.append({
                "type": "attack-pattern",
                "spec_version": "2.1",
                "id": f"attack-pattern--{ttp.replace('.', '-').lower()}",
                "name": ttp,
                "external_references": [{
                    "source_name": "mitre-attack",
                    "external_id": ttp,
                    "url": f"https://attack.mitre.org/techniques/{ttp.replace('.', '/')}",
                }],
            })

        # Assemble Bundle
        all_objects = (
            [campaign_obj, threat_actor_obj]
            + indicator_objects
            + relationship_objects
            + attack_patterns
        )

        bundle = {
            "type": "bundle",
            "id": f"bundle--{campaign_id}",
            "spec_version": "2.1",
            "objects": all_objects,
        }

        logger.info(f"STIX bundle exported for campaign {campaign_id}: {len(all_objects)} objects")
        return bundle

    except Exception as e:
        logger.error(f"STIX export failed: {e}", exc_info=True)
        return {"error": str(e)}


def _build_stix_pattern(event) -> str:
    """Build a STIX 2.1 pattern string from an IOC event."""
    channel = event.channel
    if channel in ("email",):
        return "[email-message:subject LIKE '%phishing%']"
    elif channel in ("url", "url_apk"):
        raw = (event.raw_input or "")[:200].replace("'", "\\'")
        return f"[url:value = '{raw}']"
    elif channel == "image":
        return "[file:name LIKE '%.jpg']"
    elif channel == "voice":
        return "[email-message:body LIKE '%vishing%']"
    else:
        return "[network-traffic:dst_port = 443]"

from intelligence.ioc_store import get_session, IOCEvent, Campaign
try:
    with get_session() as session:
        event_count = session.query(IOCEvent).count()
        campaign_count = session.query(Campaign).count()
        print(f"IOC Events: {event_count}")
        print(f"Campaigns: {campaign_count}")
        if event_count > 0:
            latest = session.query(IOCEvent).order_by(IOCEvent.timestamp.desc()).first()
            print(f"Latest Event: {latest.channel}, {latest.threat_level}, {latest.timestamp}")
except Exception as e:
    print(f"DB Error: {e}")

import socket
import re
from typing import Dict, Any, List

try:
    import dns.resolver
except ImportError:
    dns = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

from logger import get_logger

logger = get_logger(__name__)

def is_valid_ipv4(ip: str) -> bool:
    """Check if a string is a valid IPv4 address."""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    return bool(pattern.match(ip))

def resolve_domain(domain: str) -> List[str]:
    """Resolve a domain to its IPv4 addresses."""
    ips = []
    if not dns:
        # Fallback to standard socket if dnspython is missing
        try:
            ips.append(socket.gethostbyname(domain))
        except socket.gaierror:
            pass
        return ips
        
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for rdata in answers:
            ips.append(rdata.to_text())
    except Exception as e:
        logger.warning(f"Failed to resolve {domain}: {e}")
    return ips

def get_mx_records(domain: str) -> List[str]:
    """Get Mail Exchange (MX) records for a domain to check infrastructure legitimacy."""
    mx_records = []
    if not dns:
        return mx_records
        
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            mx_records.append(rdata.exchange.to_text())
    except Exception:
        pass # Domain might not have MX records, which is normal for some
    return mx_records

def get_asn_info(ip: str) -> Dict[str, Any]:
    """Lookup ASN and GeoIP information for an IP address."""
    if not IPWhois:
        return {"error": "ipwhois not installed"}
        
    try:
        obj = IPWhois(ip)
        res = obj.lookup_rdap(depth=1)
        
        return {
            "asn": res.get("asn"),
            "asn_cidr": res.get("asn_cidr"),
            "asn_country_code": res.get("asn_country_code"),
            "asn_description": res.get("asn_description"),
            "network_name": res.get("network", {}).get("name")
        }
    except Exception as e:
        logger.error(f"IPWhois lookup failed for {ip}: {e}")
        return {"error": str(e)}

def analyze_infrastructure(query: str) -> Dict[str, Any]:
    """
    Perform OSINT/Reputation analysis on a Domain or IP address.
    """
    logger.info(f"Analyzing infrastructure for: {query}")
    query = query.strip().lower()
    
    # Strip protocols if user pasted a URL instead of a domain
    if query.startswith("http://"): query = query[7:]
    if query.startswith("https://"): query = query[8:]
    if "/" in query: query = query.split("/")[0]
    
    report = {
        "query": query,
        "is_ip": False,
        "resolved_ips": [],
        "mx_records": [],
        "asn_info": {},
        "threat_indicators": [],
        "risk_score": 0.0,
        "risk_level": "LOW"
    }
    
    if is_valid_ipv4(query):
        report["is_ip"] = True
        report["resolved_ips"] = [query]
    else:
        # It's a domain
        report["resolved_ips"] = resolve_domain(query)
        report["mx_records"] = get_mx_records(query)
        
        if not report["resolved_ips"]:
            report["threat_indicators"].append("Domain does not resolve to any IP address (Dead domain?)")
            report["risk_score"] += 0.3
            
        if not report["mx_records"]:
            report["threat_indicators"].append("Domain lacks MX records (High risk if used for email)")
            report["risk_score"] += 0.2

    # Perform ASN lookup on the primary IP
    if report["resolved_ips"]:
        primary_ip = report["resolved_ips"][0]
        asn_data = get_asn_info(primary_ip)
        
        if "error" not in asn_data:
            report["asn_info"] = asn_data
            
            # Very basic ASN heuristic checks
            desc = (asn_data.get("asn_description") or "").lower()
            country = (asn_data.get("asn_country_code") or "").upper()
            
            # Check for bulletproof or notoriously abused hosting providers (Examples)
            high_risk_asns = ["frantech", "hostinger", "digitalocean", "hetzner", "ovh", "blazingfast"]
            if any(h in desc for h in high_risk_asns):
                report["threat_indicators"].append(f"Hosted on commonly abused infrastructure ASN: {asn_data.get('asn_description')}")
                report["risk_score"] += 0.4
                
            # Basic GeoIP anomaly checks (context-dependent in real world)
            high_risk_countries = ["RU", "KP", "IR", "SY"]
            if country in high_risk_countries:
                report["threat_indicators"].append(f"Infrastructure hosted in high-risk jurisdiction: {country}")
                report["risk_score"] += 0.5
        else:
            report["threat_indicators"].append("Failed to retrieve ASN information.")
            
    # Calculate final risk
    report["risk_score"] = min(round(report["risk_score"], 4), 1.0)
    
    if report["risk_score"] >= 0.7:
        report["risk_level"] = "HIGH"
    elif report["risk_score"] >= 0.4:
        report["risk_level"] = "MEDIUM"
        
    return report

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        print(json.dumps(analyze_infrastructure(sys.argv[1]), indent=2))

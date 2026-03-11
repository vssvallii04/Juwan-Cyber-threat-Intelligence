import os
from typing import Dict, Any, List

try:
    from scapy.all import rdpcap, IP, TCP, UDP, DNSQR, Raw
except ImportError:
    rdpcap = None

from logger import get_logger

logger = get_logger(__name__)

def parse_http_host(payload: bytes) -> str:
    """Attempt to extract the HTTP Host header from a raw TCP payload."""
    try:
        text = payload.decode('utf-8', errors='ignore')
        if "HTTP/" in text:
            for line in text.split("\r\n"):
                if line.lower().startswith("host:"):
                    return line.split(":", 1)[1].strip()
    except Exception:
        pass
    return None

def analyze_pcap(file_path: str) -> Dict[str, Any]:
    """
    Parse a .pcap file to extract network indicators of compromise (IOCs).
    Extracts Unique IPs, DNS Queries, and HTTP Hosts.
    """
    logger.info(f"Analyzing PCAP file: {file_path}")
    
    if not os.path.exists(file_path):
        return {"error": "PCAP file not found"}
        
    if not rdpcap:
        return {"error": "scapy library not installed"}
        
    report = {
        "file_name": os.path.basename(file_path),
        "packet_count": 0,
        "unique_ips": [],
        "dns_queries": [],
        "http_hosts": [],
        "suspicious_indicators": [],
        "threat_level": "LOW",
        "confidence": 0.0
    }
    
    ips = set()
    dns_requests = set()
    http_hosts = set()
    
    score = 0.0
    
    try:
        # Load packets into memory (Warning: bad for massive PCAPs, fine for standard malware samples)
        packets = rdpcap(file_path)
        report["packet_count"] = len(packets)
        
        for pkt in packets:
            # 1. IP Connections
            if IP in pkt:
                ips.add(pkt[IP].src)
                ips.add(pkt[IP].dst)
                
            # 2. DNS Queries (often used by malware for C2 resolution or DGA)
            if pkt.haslayer(DNSQR):
                query = pkt[DNSQR].qname.decode('utf-8', errors='ignore').rstrip('.')
                if query:
                    dns_requests.add(query)
                    
            # 3. HTTP Payloads (Check for plaintext C2 beacons)
            if pkt.haslayer(TCP) and pkt.haslayer(Raw):
                if pkt[TCP].dport == 80 or pkt[TCP].sport == 80:
                    host = parse_http_host(pkt[Raw].load)
                    if host:
                        http_hosts.add(host)

        # Remove local/multicast noise
        ignore_ips = {"127.0.0.1", "0.0.0.0", "255.255.255.255"}
        report["unique_ips"] = [ip for ip in ips if ip not in ignore_ips and not ip.startswith("169.254.")]
        report["dns_queries"] = list(dns_requests)
        report["http_hosts"] = list(http_hosts)
        
        # Heuristics Scoring
        if report["http_hosts"]:
            # High severity if we see plaintext HTTP in a modern capture
            report["suspicious_indicators"].append("Plaintext HTTP traffic detected (Potential C2 beacon)")
            score += 0.3
            
        if len(report["dns_queries"]) > 50:
            # Possible DGA (Domain Generation Algorithm) activity
            report["suspicious_indicators"].append(f"High volume of DNS queries ({len(report['dns_queries'])}). Possible DGA.")
            score += 0.4
            
        if any(ip.startswith("91.") or ip.startswith("185.") or ip.startswith("45.") for ip in report["unique_ips"]):
            # Loose heuristic for notoriously abused ASNs
            score += 0.2
            
    except Exception as e:
        logger.error(f"Error parsing PCAP: {e}")
        report["error"] = str(e)
        
    # Cap score at 1.0
    report["confidence"] = min(round(score, 4), 1.0)
    
    if report["confidence"] >= 0.7:
        report["threat_level"] = "HIGH"
    elif report["confidence"] >= 0.4:
        report["threat_level"] = "MEDIUM"
        
    return report

if __name__ == "__main__":
    import sys
    import json
    if len(sys.argv) > 1:
        print(json.dumps(analyze_pcap(sys.argv[1]), indent=2))

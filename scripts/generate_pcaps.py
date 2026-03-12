from scapy.all import IP, TCP, DNS, DNSQR, wrpcap
import os

os.makedirs("samples", exist_ok=True)

# 1. Legit PCAP (Standard HTTP-like traffic style)
pkts_legit = [
    IP(dst="8.8.8.8")/TCP(dport=53),
    IP(dst="1.1.1.1")/TCP(dport=443)
]
wrpcap("samples/legit_traffic.pcap", pkts_legit)

# 2. Malicious PCAP (DGA-like DNS traffic)
pkts_malicious = [
    IP(dst="8.8.8.8")/DNS(rd=1, qd=DNSQR(qname="xvz123malware.com")),
    IP(dst="8.8.8.8")/DNS(rd=1, qd=DNSQR(qname="abc987phish.net")),
    IP(dst="8.8.8.8")/DNS(rd=1, qd=DNSQR(qname="qwe000c2.org"))
]
wrpcap("samples/malicious_traffic.pcap", pkts_malicious)

print("PCAP samples generated in samples/")

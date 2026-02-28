"""
Network Anomaly Detector
=========================
Author: Shubham Singh | github.com/shubhamsingh99
Description: Analyzes .pcap files to detect port scans, beaconing,
             DNS tunneling, and lateral movement patterns.

Requirements: pip install scapy pandas
"""

from scapy.all import rdpcap, IP, TCP, UDP, DNS, DNSQR
from collections import defaultdict, Counter
import pandas as pd
import json
from datetime import datetime
import math


# ─── ANALYSIS FUNCTIONS ──────────────────────────────────────────────────────

def detect_port_scan(packets) -> list:
    """
    Detect port scanning activity (SYN scan pattern).
    Alert when a single source hits >20 unique ports on one destination.
    """
    alerts = []
    syn_map = defaultdict(set)  # src_ip -> set of dst_ports

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            flags = pkt[TCP].flags
            # SYN flag only (no ACK) = SYN scan
            if flags == 0x02:
                src = pkt[IP].src
                dst_port = pkt[TCP].dport
                syn_map[src].add(dst_port)

    for src_ip, ports in syn_map.items():
        if len(ports) > 20:
            alerts.append({
                "type": "PORT_SCAN",
                "severity": "HIGH",
                "mitre": "T1046 - Network Service Discovery",
                "source_ip": src_ip,
                "unique_ports_scanned": len(ports),
                "sample_ports": sorted(list(ports))[:10],
                "recommendation": f"Block {src_ip} at firewall. Investigate host for compromise."
            })

    return alerts


def detect_beaconing(packets, interval_threshold_std=2.0) -> list:
    """
    Detect C2 beaconing — regular, periodic outbound connections.
    Low standard deviation in connection intervals = likely beaconing.
    """
    alerts = []
    connection_times = defaultdict(list)

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].flags == 0x02:  # SYN packets (new connections)
                key = f"{pkt[IP].src}->{pkt[IP].dst}:{pkt[TCP].dport}"
                connection_times[key].append(float(pkt.time))

    for conn, times in connection_times.items():
        if len(times) < 5:
            continue

        times.sort()
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        mean_interval = sum(intervals) / len(intervals)
        variance = sum((x - mean_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = math.sqrt(variance)

        # Low std deviation relative to mean = regular beaconing
        if std_dev < interval_threshold_std and mean_interval < 300:
            alerts.append({
                "type": "BEACONING_DETECTED",
                "severity": "CRITICAL",
                "mitre": "T1071 - Application Layer Protocol / T1132 - Data Encoding",
                "connection": conn,
                "connection_count": len(times),
                "avg_interval_seconds": round(mean_interval, 2),
                "std_deviation": round(std_dev, 4),
                "recommendation": "Investigate endpoint for malware. Check process making outbound connections."
            })

    return alerts


def detect_dns_tunneling(packets) -> list:
    """
    Detect DNS tunneling — abnormally long DNS queries or high query volume.
    Threshold: query > 50 chars or >100 queries to same domain in session.
    """
    alerts = []
    dns_queries = defaultdict(list)
    long_queries = []

    for pkt in packets:
        if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
            query = pkt[DNSQR].qname.decode("utf-8", errors="ignore").rstrip(".")
            src_ip = pkt[IP].src if pkt.haslayer(IP) else "unknown"

            # Long subdomain = possible data exfil
            if len(query) > 50:
                long_queries.append({
                    "source": src_ip,
                    "query": query,
                    "length": len(query)
                })

            # Track domain query frequency
            base_domain = ".".join(query.split(".")[-2:]) if "." in query else query
            dns_queries[f"{src_ip}->{base_domain}"].append(query)

    if long_queries:
        alerts.append({
            "type": "DNS_TUNNELING_SUSPECTED",
            "severity": "HIGH",
            "mitre": "T1071.004 - Application Layer Protocol: DNS",
            "evidence": f"{len(long_queries)} abnormally long DNS queries detected",
            "samples": long_queries[:5],
            "recommendation": "Block suspicious domains at DNS resolver. Capture full DNS traffic for analysis."
        })

    for conn, queries in dns_queries.items():
        if len(queries) > 100:
            alerts.append({
                "type": "HIGH_VOLUME_DNS",
                "severity": "MEDIUM",
                "mitre": "T1048 - Exfiltration Over Alternative Protocol",
                "connection": conn,
                "query_count": len(queries),
                "recommendation": "Investigate DNS query patterns. Check for data exfiltration."
            })

    return alerts


def detect_lateral_movement(packets) -> list:
    """
    Detect lateral movement — internal hosts connecting to SMB (445),
    RDP (3389), WinRM (5985), or SSH (22) ports on other internal hosts.
    """
    alerts = []
    internal_ranges = ["10.", "192.168.", "172.16.", "172.17.", "172.18."]
    lateral_ports = {445: "SMB", 3389: "RDP", 5985: "WinRM", 22: "SSH", 135: "RPC"}

    lateral_connections = defaultdict(set)

    for pkt in packets:
        if pkt.haslayer(TCP) and pkt.haslayer(IP):
            if pkt[TCP].flags == 0x02:
                src = pkt[IP].src
                dst = pkt[IP].dst
                dport = pkt[TCP].dport

                # Internal to internal lateral movement
                is_internal_src = any(src.startswith(r) for r in internal_ranges)
                is_internal_dst = any(dst.startswith(r) for r in internal_ranges)

                if is_internal_src and is_internal_dst and dport in lateral_ports:
                    key = f"{src}"
                    lateral_connections[key].add(f"{dst}:{dport}({lateral_ports[dport]})")

    for src_ip, targets in lateral_connections.items():
        if len(targets) > 3:
            alerts.append({
                "type": "LATERAL_MOVEMENT",
                "severity": "CRITICAL",
                "mitre": "T1021 - Remote Services",
                "source_ip": src_ip,
                "targets_accessed": len(targets),
                "sample_targets": list(targets)[:5],
                "recommendation": "IMMEDIATE: Isolate source host. Investigate for compromise and credential theft."
            })

    return alerts


# ─── MAIN ANALYZER ───────────────────────────────────────────────────────────

def analyze_pcap(pcap_file: str) -> None:
    """Run full anomaly detection suite on a pcap file."""
    print(f"\n[*] Loading pcap: {pcap_file}")
    packets = rdpcap(pcap_file)
    print(f"[*] Loaded {len(packets)} packets")
    print("=" * 60)

    all_alerts = []

    print("[*] Checking for port scans...")
    all_alerts += detect_port_scan(packets)

    print("[*] Checking for beaconing activity...")
    all_alerts += detect_beaconing(packets)

    print("[*] Checking for DNS tunneling...")
    all_alerts += detect_dns_tunneling(packets)

    print("[*] Checking for lateral movement...")
    all_alerts += detect_lateral_movement(packets)

    print(f"\n{'='*60}")
    print(f"🚨 ANALYSIS COMPLETE — {len(all_alerts)} alerts found")
    print(f"{'='*60}\n")

    severity_counts = Counter(a["severity"] for a in all_alerts)
    print(f"  CRITICAL: {severity_counts.get('CRITICAL', 0)}")
    print(f"  HIGH:     {severity_counts.get('HIGH', 0)}")
    print(f"  MEDIUM:   {severity_counts.get('MEDIUM', 0)}")

    for alert in all_alerts:
        print(f"\n[{alert['severity']}] {alert['type']}")
        print(f"  MITRE: {alert['mitre']}")
        for k, v in alert.items():
            if k not in ("type", "severity", "mitre"):
                print(f"  {k}: {v}")

    # Save report
    report = {
        "analyst": "Shubham Singh",
        "timestamp": datetime.utcnow().isoformat(),
        "pcap_file": pcap_file,
        "total_packets": len(packets),
        "total_alerts": len(all_alerts),
        "alerts": all_alerts
    }
    output = f"network_analysis_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.json"
    with open(output, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\n[+] Report saved: {output}")


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_pcap(sys.argv[1])
    else:
        print("Usage: python network_anomaly_detector.py <capture.pcap>")
        print("Example: python network_anomaly_detector.py traffic.pcap")

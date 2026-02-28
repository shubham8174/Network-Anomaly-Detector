# 🌐 Network Anomaly Detector

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-pcap-009639?style=for-the-badge)
![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-FF0000?style=for-the-badge)


> Analyzes network packet captures (.pcap) to detect port scans, C2 beaconing, DNS tunneling, and lateral movement — with automatic MITRE ATT&CK mapping and severity classification.

---

## 📌 Overview

Network traffic analysis is a critical blue team skill. This tool processes raw `.pcap` files captured via Wireshark or network taps and automatically surfaces the most dangerous attacker behaviors — the ones that traditional signature-based IDS often miss.

Built on real-world SOC experience analyzing network telemetry and investigating suspicious authentication events across enterprise environments.

---

## ✨ Detection Capabilities

| Detection | MITRE Technique | How It Works |
|---|---|---|
| **Port Scanning** | T1046 | Flags single source hitting 20+ unique ports via SYN packets |
| **C2 Beaconing** | T1071 | Low standard deviation in connection intervals = periodic callback |
| **DNS Tunneling** | T1071.004 | Abnormally long subdomains or high-volume DNS to single domain |
| **Lateral Movement** | T1021 | Internal-to-internal SMB/RDP/WinRM/SSH connections |

---

## 🛠️ Installation

```bash
git clone https://github.com/shubham8174/Network-Anomaly-Detector.git
cd Network-Anomaly-Detector
pip install scapy pandas
```

---

## 🚀 Usage

```bash
# Analyze a pcap file
python network_anomaly_detector.py capture.pcap

# Capture live traffic first with tcpdump, then analyze
tcpdump -i eth0 -w capture.pcap
python network_anomaly_detector.py capture.pcap
```

**Sample Output:**
```
[*] Loading pcap: capture.pcap
[*] Loaded 45823 packets
============================================================
[*] Checking for port scans...
[*] Checking for beaconing activity...
[*] Checking for DNS tunneling...
[*] Checking for lateral movement...

============================================================
🚨 ANALYSIS COMPLETE — 3 alerts found
============================================================

  CRITICAL: 1
  HIGH:     2
  MEDIUM:   0

[CRITICAL] LATERAL_MOVEMENT
  MITRE: T1021 - Remote Services
  source_ip: 192.168.1.45
  targets_accessed: 7
  sample_targets: ['192.168.1.10:445(SMB)', '192.168.1.20:3389(RDP)']
  recommendation: IMMEDIATE: Isolate source host.

[HIGH] PORT_SCAN
  MITRE: T1046 - Network Service Discovery
  source_ip: 10.0.0.15
  unique_ports_scanned: 1024

[HIGH] DNS_TUNNELING_SUSPECTED
  MITRE: T1071.004 - Application Layer Protocol: DNS
  evidence: 12 abnormally long DNS queries detected
```

---

## 📁 Project Structure

```
Network-Anomaly-Detector/
│
├── network_anomaly_detector.py   # Main detection engine
├── samples/                      # Sample pcap files for testing
├── reports/                      # JSON analysis reports
└── README.md
```

---

## 🔬 Technical Deep Dive

### Beaconing Detection Algorithm
Beaconing is detected by measuring the **standard deviation of connection intervals**. Legitimate traffic is irregular; malware callbacks are periodic. A low std deviation (< 2.0 seconds) combined with short intervals (< 300 seconds) triggers a CRITICAL alert.

### DNS Tunneling Heuristics
- Subdomains > 50 characters (data encoded in DNS queries)
- 100+ queries to same base domain in a session (high-volume exfiltration)

---

## 🔮 Roadmap

- [ ] Live interface capture mode (real-time alerting)
- [ ] Integration with Zeek/Suricata logs
- [ ] Machine learning baseline for anomaly scoring
- [ ] SIEM integration via syslog output

---

## 👤 Author

**Shubham Singh**
MSc Cyber Security — University of Southampton 🇬🇧
Information Security Analyst | Network Security | CCNA

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?style=flat&logo=linkedin)](https://www.linkedin.com/in/shubham-singh99/)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=flat&logo=github)](https://github.com/shubham8174)


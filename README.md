# Network Intrusion Detection System for IoT
**Plymouth University — PUSL3190 Computing Project**
**Student:** Athukorala Athukorala | **ID:** 10953295

## Project Overview
A cost-effective, open-source NIDS built using Snort, 
designed to detect attacks in IoT-integrated networks.

## Lab Setup
- Kali Linux (192.168.243.10) — Attacker
- Metasploitable2 (192.168.243.20) — IoT victim
- Snort on Windows host — IDS engine

## Attacks Detected
- Nmap SYN port scanning
- ICMP/TCP DoS flooding
- FTP brute force


## Files
- `monitor.py` — Python central monitoring dashboard
- `local.rules` — Custom Snort detection rules
- `snort.conf` — Snort configuration
- `start_monitor.bat` — Easy launch script

## How to Run
1. Start Snort
2. Run `start_monitor.bat`
3. Launch attacks from Kali
4. Watch dashboard for live alerts

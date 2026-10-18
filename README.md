<div align="center">

# 🛡️ Enterprise Network Defense & DoS Mitigation Lab
### *VirtualBox • pfSense CE • Kali Linux • Ubuntu Desktop • Custom Python IDS/IPS*

[![VirtualBox](https://img.shields.io/badge/VirtualBox-7.x-2D62B5?style=for-the-badge&logo=virtualbox&logoColor=white)](https://www.virtualbox.org/)
[![pfSense](https://img.shields.io/badge/pfSense-CE_2.7.x-black?style=for-the-badge&logo=pfsense&logoColor=red)](https://www.pfsense.org/)
[![Kali Linux](https://img.shields.io/badge/Kali_Linux-Attacker-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Ubuntu](https://img.shields.io/badge/Ubuntu_22.04-Victim-E95420?style=for-the-badge&logo=ubuntu&logoColor=white)](https://ubuntu.com/)
[![Python](https://img.shields.io/badge/Engine-Python_3.10+-3776AB?style=for-the-badge&logo=python&logoColor=yellow)](https://www.python.org/)
[![Wireshark](https://img.shields.io/badge/Packet_Analysis-Wireshark-1679A7?style=for-the-badge&logo=wireshark&logoColor=white)](https://www.wireshark.org/)

<p align="center">
  A hands-on, enterprise-grade cybersecurity lab simulating realistic <b>Layer 3 & 4 Denial-of-Service (DoS) floods</b>, network packet inspection, edge firewall containment, and host-level dynamic threshold mitigation.
</p>

[Lab Overview](#-lab-overview) •
[Architecture](#-network-architecture) •
[Prerequisites](#-prerequisites--environment) •
[Deployment Guide](#-step-by-step-deployment) •
[Attack Simulation](#-attack-simulation) •
[Python Engine](#-automated-dos-blocker-engine) •
[Verification](#-dual-mitigation--verification)

</div>

---

## 📌 Lab Overview

This project sets up an isolated, dual-homed security boundary inside Oracle VirtualBox[cite: 3, 4]:
* **Untrusted Zone (WAN):** Features a **Kali Linux** node simulating an external adversary launching high-frequency ICMP & TCP SYN floods[cite: 3, 7, 8].
* **Perimeter Gateway:** A **pfSense 2.7.x** firewall enforcing stateful packet inspection, dynamic routing, and network segmentation[cite: 3, 4].
* **Protected Zone (LAN):** An isolated `LabNet` segment housing an **Ubuntu Desktop** workstation instrumented with Wireshark and an active, automated Python mitigation daemon[cite: 3, 5, 8].

---

## 🏛️ Network Architecture

                              =================================
                              🌐 Physical Host / Home Network
                                    (Subnet: 192.168.0.0/24)
                              =================================
                                        |            |
                          Bridged (eth0)|            | Bridged (vtnet0)
                                        v            v
+--------------------------------+                  +--------------------------------+|    🗡️ Kali Linux (Attacker)     |                  |     🔥 pfSense Edge Gateway    ||    IP: 192.168.0.200/24        |                  |     WAN: 192.168.0.254/24      ||    Tool: hping3 Flooding Engine|                  |     LAN: 192.168.1.1/24        |+--------------------------------+                  +--------------------------------+|| 🔒 Internal Network|    VirtualBox: "LabNet"v+--------------------------------+|    🎯 Ubuntu Workstation (Host)||    IP: 192.168.1.100/24        ||    - Deep Packet Inspection    ||    - Auto DoS Blocker Daemon   |+--------------------------------+
### 📋 Interface & IP Schema

| Device | Interface | Adapter Type | IP / Subnet | Role & Function |
| :--- | :--- | :--- | :--- | :--- |
| **Default Gateway** | Physical | Host Adapter | `192.168.0.1/24` | Upstream ISP Router & Default Gateway[cite: 3] |
| **Kali Linux** | `eth0` | Bridged Adapter | `192.168.0.200/24` | External Adversary Node[cite: 3, 7] |
| **pfSense (WAN)** | `vtnet0` | Bridged Adapter | `192.168.0.254/24` | External Firewall Interface[cite: 3, 5] |
| **pfSense (LAN)** | `vtnet1` | Internal (`LabNet`) | `192.168.1.1/24` | Secure Internal Gateway & DHCP Server[cite: 3, 5, 6] |
| **Ubuntu Desktop** | `eth0` | Internal (`LabNet`) | `192.168.1.100/24` | Protected Workload / Target Machine[cite: 3, 7] |

---

## 🧰 Prerequisites & Environment

* **Hypervisor:** VirtualBox ≥ 7.0[cite: 4]
* **Host Hardware Specs:** 8 GB+ RAM, 4 CPU Cores, 40 GB Free Disk Space[cite: 4]
* **Operating System Images:**
  * [pfSense CE 2.7.x amd64](https://www.pfsense.org/download/)[cite: 4]
  * [Kali Linux amd64 (Latest)](https://www.kali.org/get-kali/)[cite: 4]
  * [Ubuntu 22.04 LTS Desktop](https://ubuntu.com/download/desktop)[cite: 4]

---

## 🚀 Step-by-Step Deployment

### 1️⃣ pfSense Firewall Provisioning
1. **VM Specs:** 2 vCPUs, 2 GB RAM, 20 GB VDI Storage[cite: 4].
2. **Network Adapters:**
   * **Adapter 1:** Bridged Adapter (Physical NIC)[cite: 4]
   * **Adapter 2:** Internal Network (`LabNet`)[cite: 4]
3. **Console Interface Setup:**
   * Set `vtnet0` as WAN (DHCP via home router).
   * Set `vtnet1` as LAN (Static `192.168.1.1/24`)[cite: 3, 5].
4. **Initial Management Rule:**
   Drop into shell via the console menu and temporarily unlock the packet filter:
   ```bash
   pfSense -d
WebGUI Rules Configuration:
Log into https://192.168.0.254 (Default: admin / pfsense):   Under Firewall > Rules > WAN, allow HTTPS access from your home subnet.   Under Services > DHCP Server > LAN, set the range to 192.168.1.100 – 192.168.1.199 and enable the service.   2️⃣ Target Host Provisioning (Ubuntu Victim)VM Specs: 2 vCPUs, 2 GB RAM, 15 GB Disk, Adapter 1 set to Internal Network (LabNet).   Verify DHCP lease assignment and internet reachability:   Baship a show eth0
ping -c 3 1.1.1.1
Install required inspection and packet analysis utilities:   Bashsudo apt update && sudo apt install -y wireshark python3 iptables net-tools
3️⃣ Attacker Node Setup (Kali Linux)VM Specs: 2 vCPUs, 2 GB RAM, 15 GB Disk, Adapter 1 set to Bridged Adapter[cite: 5].Identify assigned WAN IP:   Baship a show eth0
Add Static Routing: Route LabNet target traffic through the pfSense WAN address:   Bashsudo ip route add 192.168.1.0/24 via 192.168.0.254
Verify routing reachability to the target host:   Bashping -c 3 192.168.1.100
⚡ Attack SimulationSimulate high-throughput DoS conditions from Kali toward the internal target:   Bash# 1. ICMP Volumetric Flood
sudo hping3 -1 --flood 192.168.1.100

# 2. TCP SYN Flood (Port 80)
sudo hping3 --flood -S -p 80 192.168.1.100
Launch Wireshark on the Ubuntu node to inspect frame saturation and throughput spikes live:   Bashsudo wireshark &
🧠 Automated DoS Blocker EngineLocated on the victim machine as dos_blocker.py. It leverages low-level Linux raw sockets (AF_PACKET) to monitor Layer-3/4 incoming frames in real-time, calculates rolling packet rates, and immediately adds a kernel-level iptables drop rule when flooding behavior is detected.Python#!/usr/bin/env python3
"""
dos_blocker.py
Real-time Dynamic Socket Sniffer & Host-level IPS Engine
"""

import socket
import struct
import time
import subprocess
import sys
from collections import defaultdict

# --- CONFIGURATION ---
PACKET_THRESHOLD = 150       # Max incoming packets per time window
CHECK_INTERVAL = 1.0         # Sliding window evaluation (seconds)
WHITELIST = {"127.0.0.1", "192.168.1.1"}

blocked_ips = set()
packet_counters = defaultdict(int)

def block_ip(ip_address: str):
    """Enforces an immediate iptables DROP rule on the host kernel."""
    if ip_address in blocked_ips or ip_address in WHITELIST:
        return

    print(f"\n[🚨 THREAT DETECTED] Volumetric flood signature matched from: {ip_address}")
    print(f"[🛡️ MITIGATION] Injecting kernel rule: iptables -I INPUT -s {ip_address} -j DROP")
    
    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        blocked_ips.add(ip_address)
        print(f"[✅ ACTIVE] Ingress packets from {ip_address} are successfully dropped.\n")
    except subprocess.CalledProcessError as err:
        print(f"[❌ ERROR] Failed to update iptables: {err}")

def parse_ipv4_source(raw_data: bytes):
    """Extracts the source IPv4 address from raw Ethernet frame payload."""
    ip_header = raw_data # Strip Layer 2 Ethernet header (14 bytes)
    unpacked_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
    return socket.inet_ntoa(unpacked_data[8])

def main():
    if sys.platform != "linux":
        print("[!] This script requires Linux raw socket support (AF_PACKET).")
        sys.exit(1)

    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except PermissionError:
        print("[-] Root privileges required. Execute with: sudo python3 dos_blocker.py")
        sys.exit(1)

    print("=" * 65)
    print(" 🛡️  ACTIVE DEFENSE: Real-Time Host-Level DoS Mitigation Engine")
    print("=" * 65)
    print(f"[*] Monitoring Interface : AF_PACKET Raw Socket (IPv4)")
    print(f"[*] Burst Rate Trigger   : > {PACKET_THRESHOLD} packets / {CHECK_INTERVAL}s")
    print("[*] Status               : Sniffing ingress frames...\n")

    window_start = time.time()

    while True:
        raw_packet, _ = raw_sock.recvfrom(65535)
        source_ip = parse_ipv4_source(raw_packet)

        if source_ip not in blocked_ips and source_ip not in WHITELIST:
            packet_counters[source_ip] += 1

        elapsed = time.time() - window_start
        if elapsed >= CHECK_INTERVAL:
            for ip, count in list(packet_counters.items()):
                if count > PACKET_THRESHOLD:
                    print(f"[!] Traffic Alert: Observed {count} pkts/{CHECK_INTERVAL}s from {ip}")
                    block_ip(ip)

            packet_counters.clear()
            window_start = time.time()

if __name__ == "__main__":
    main()
Running the Python EngineBashchmod +x dos_blocker.py
sudo python3 dos_blocker.py
🔒 Dual Mitigation & Verification                      +---------------------------------------+
                      |          DoS Attack Stream            |
                      +---------------------------------------+
                                          |
                      +-------------------+-------------------+
                      |                                       |
                      v                                       v
         [ Layer 1: Edge Mitigation ]            [ Layer 2: Host Mitigation ]
             pfSense WAN Rule                        Python dos_blocker.py
                      |                                       |
             Drops at Boundary                       Drops via Linux Kernel
        (Protects LAN & Bandwidth)                  (Zero-Config Endpoint Host)
1. Perimeter Mitigation (pfSense Firewall)Navigate to Firewall > Rules > WAN and click Add (Top).   Action: Block   Source: 192.168.0.200 (Kali IP)   Destination: 192.168.1.100 (Ubuntu IP)   Logging: Check "Log packets handled by this rule"   Description: Block Kali DoS Attack   Click Save and Apply Changes.   2. Multi-Tier VerificationWireshark Live Metrics: The packet stream immediately plunges to 0 packets/sec upon activation of the pfSense rule or the host blocker.   pfSense System Logs: Navigate to Status > System Logs > Firewall to observe dropped packets flagged with red block icons.   Kernel Rule Verification: Run sudo iptables -L INPUT -v -n to review active byte and packet drop statistics incremented by the Python daemon.📜 Repository Structure├── README.md               # Complete lab architecture and walkthrough
├── scripts/
│   └── dos_blocker.py      # Automated socket sniffer & dynamic iptables blocker
└── docs/
    └── architecture.png    # Lab network topology diagram

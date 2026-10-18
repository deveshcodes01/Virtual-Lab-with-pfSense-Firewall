# Virtual-Lab-with-pfSense-Firewall

# Enterprise Network Defense & DoS Mitigation Lab (pfSense + Python Blocker)

An end-to-end cybersecurity homelab designed in Oracle VirtualBox to simulate, detect, and mitigate Denial-of-Service (DoS) attacks[cite: 1, 3, 4]. The lab provisions a dual-homed **pfSense** perimeter firewall separating an external attacker zone (**Kali Linux**) from an isolated internal segment (**Ubuntu Desktop** victim)[cite: 3]. Traffic analysis is captured via Wireshark, with attack mitigation performed via pfSense firewall rules and an automated Python-based socket packet inspection/blocking engine[cite: 8, 9].

---

## Lab Architecture

                    +---------------------------------------------+
                    |           Physical Host / Home LAN          |
                    |              (192.168.0.0/24)               |
                    +---------------------------------------------+
                                   |               |
                     Bridged (eth0)|               | Bridged (vtnet0)
                                   v               v
            +----------------------------+   +----------------------------+
            |    Kali Linux (Attacker)   |   |      pfSense Firewall      |
            |     192.168.0.200/24       |   |   WAN: 192.168.0.254/24    |
            |   [hping3 Flooding Node]   |   +----------------------------+
            +----------------------------+                 |
                                                           | Internal Network: "LabNet"
                                                           | LAN: 192.168.1.1/24 (vtnet1)
                                                           v
                                             +----------------------------+
                                             |   Ubuntu Desktop (Victim)  |
                                             |     192.168.1.100/24       |
                                             | [Wireshark & Python Blocker]
                                             +----------------------------+

### Network Topology & Interface Mapping

| Node | Interface | VirtualBox Adapter Mode | Assigned IP / Subnet | Role / Description |
| :--- | :--- | :--- | :--- | :--- |
| **Physical Router** | Gateway | Physical Host NIC | `192.168.0.1/24` | Upstream internet gateway & DHCP[cite: 3] |
| **Kali Linux** | `eth0` | Bridged Adapter | `192.168.0.200/24` (DHCP) | Simulated external attacker executing floods[cite: 3, 7] |
| **pfSense (WAN)** | `vtnet0` | Bridged Adapter | `192.168.0.254/24` (DHCP) | Perimeter gateway facing untrusted zone[cite: 3, 5] |
| **pfSense (LAN)** | `vtnet1` | Internal Network (`LabNet`) | `192.168.1.1/24` | Internal gateway & DHCP server (`.100`–`.199`) |
| **Ubuntu Desktop** | `eth0` | Internal Network (`LabNet`) | `192.168.1.100/24` | Target host running services, Wireshark, & DoS blocker[cite: 3, 7, 8] |

---

## Lab Prerequisites

* **Virtualization Engine:** Oracle VirtualBox 7.x or higher[cite: 4]
* **Host Hardware Resources:** Minimum 8 GB RAM, 4 vCPUs, 40 GB free storage[cite: 4]
* **OS Images:**
  * pfSense CE 2.7.x (`amd64`)[cite: 4]
  * Kali Linux 2024.x/Current (`amd64`)[cite: 4]
  * Ubuntu 22.04 LTS Desktop (`amd64`)[cite: 4]

---

## Step-by-Step Setup Guide

### 1. pfSense Firewall Deployment
1. Create a VM with 2 vCPUs, 2 GB RAM, and a 20 GB disk[cite: 4].
2. Configure **Adapter 1** as **Bridged Adapter** and **Adapter 2** as **Internal Network** (Name: `LabNet`)[cite: 4].
3. Boot the installer, accept default filesystem configurations, and assign interfaces:
   * `WAN` -> `vtnet0` (Acquires IP via upstream DHCP)
   * `LAN` -> `vtnet1` (Static: `192.168.1.1/24`)[cite: 3, 5]
4. Navigate to the shell from the pfSense console and run `pfSsh.php` or temporarily disable packet filtering to enable initial WAN administration:
   ```bash
   pfSense -d
(Alternatively, configure pfSense WebGUI directly through a browser on https://192.168.0.254).
5. Under Firewall > Rules > WAN, create an initial access rule:   Action: Pass   Protocol: TCP   Source: Home LAN subnet (192.168.0.0/24)[cite: 3, 6]Destination: WAN address (Port 443)   Enable LAN DHCP under Services > DHCP Server > LAN with the pool range 192.168.1.100 – 192.168.1.199.   2. Victim Machine (Ubuntu Desktop)Attach Adapter 1 to Internal Network (LabNet)[cite: 5].Boot the machine and verify IP assignment:Baship a show eth0
ping -c 3 1.1.1.1
Install Wireshark and Python raw-socket dependencies:   Bashsudo apt update && sudo apt install -y wireshark python3 iptables
3. Attacker Machine (Kali Linux)Attach Adapter 1 to Bridged Adapter[cite: 5].Verify local WAN subnet IP assignment:   Baship a show eth0
Add a persistent static route directing traffic toward the internal LabNet segment via pfSense's WAN interface:   Bashsudo ip route add 192.168.1.0/24 via <PFSENSE_WAN_IP>
Verify end-to-end reachability to the victim node:   Bashping -c 3 192.168.1.100
Simulating the DoS FloodTo emulate malicious network behavior, launch high-volume packet floods from the Kali Linux VM toward the Ubuntu target.   ICMP Ping FloodBashsudo hping3 -1 --flood 192.168.1.100
TCP SYN Flood (Port 80)Bashsudo hping3 --flood -S -p 80 192.168.1.100
Inspect packet ingestion and interface saturation live in Wireshark on the Ubuntu target:   Bashsudo wireshark &
Automated DoS Blocker ScriptThis custom Python script runs on the victim node. It uses raw Linux AF_PACKET sockets to parse Layer 3/4 headers, track ingress packet frequency per source IP over a rolling dynamic time window, and trigger kernel-level iptables drop rules when rate limits are breached.dos_blocker.pyPython#!/usr/bin/env python3
"""
Dynamic Threshold DoS Blocker
Sniffs incoming IP packets, calculates per-source throughput, and executes 
host-level iptables mitigations against volumetric flooding.
"""

import socket
import struct
import time
import subprocess
import sys
from collections import defaultdict

# --- CONFIGURATION THRESHOLDS ---
PACKET_THRESHOLD = 150       # Maximum allowed packets per sampling interval
CHECK_INTERVAL = 1.0         # Sampling window in seconds
BLOCKED_IPS = set()
packet_counts = defaultdict(int)

def block_ip(ip_address: str):
    """Appends an iptables DROP rule for the offending source IP."""
    if ip_address in BLOCKED_IPS:
        return
    
    print(f"[!] Alert: High packet volume detected from {ip_address}")
    print(f"[*] Applying firewall drop rule: iptables -I INPUT -s {ip_address} -j DROP")
    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"], check=True)
        BLOCKED_IPS.add(ip_address)
        print(f"[+] Successfully blocked {ip_address} at host level.")
    except subprocess.CalledProcessError as err:
        print(f"[-] Failed to execute iptables command: {err}")

def parse_ipv4_header(raw_data: bytes):
    """Unpacks IPv4 packets to extract the source IP address."""
    ip_header = raw_data # Strip Layer 2 Ethernet header
    unpacked_data = struct.unpack('!BBHHHBBH4s4s', ip_header)
    src_ip = socket.inet_ntoa(unpacked_data[8])
    return src_ip

def main():
    try:
        # AF_PACKET raw socket captures incoming Layer 2 Ethernet frames on Linux
        raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except PermissionError:
        print("[-] Script requires root privileges to open raw sockets. Run with sudo.")
        sys.exit(1)

    print("[*] DoS Blocker Engine started. Monitoring network traffic...")
    last_reset = time.time()

    while True:
        raw_data, _ = raw_socket.recvfrom(65535)
        src_ip = parse_ipv4_header(raw_data)

        if src_ip not in BLOCKED_IPS:
            packet_counts[src_ip] += 1

        current_time = time.time()
        if current_time - last_reset >= CHECK_INTERVAL:
            for ip, count in list(packet_counts.items()):
                if count > PACKET_THRESHOLD and ip not in BLOCKED_IPS:
                    block_ip(ip)
            
            # Reset counters for the next window
            packet_counts.clear()
            last_reset = current_time

if __name__ == "__main__":
    main()
Executing the BlockerBashsudo chmod +x dos_blocker.py
sudo python3 dos_blocker.py
Dual Mitigation & Verification1. Perimeter Firewall Rule (pfSense WebGUI)Go to Firewall > Rules > WAN.   Click Add (Top) to insert a rule before general permit statements:   Action: Block   Interface: WAN   Address Family: IPv4Protocol: AnySource: Single host or alias -> 192.168.0.200 (Kali IP)   Destination: Single host or alias -> 192.168.1.100 (Ubuntu IP)   Log: Check "Log packets that are handled by this rule"   Description: Block Kali DoS Attack   Click Save and Apply Changes.   2. VerificationWireshark Stream Analysis: Observe packet capture graphs dropping to 0 packets/sec instantly upon rule application.   pfSense System Logs: Navigate to Status > System Logs > Firewall to confirm dropped packets with red block flags[cite: 8].Host iptables Rules (Python Engine Output): Run sudo iptables -L INPUT -v -n on Ubuntu to verify dropped volumetric frames.

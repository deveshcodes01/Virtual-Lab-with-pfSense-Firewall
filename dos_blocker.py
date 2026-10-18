#!/usr/bin/env python3
"""
dos_blocker.py
Dynamic Threshold Layer-3/4 DoS Blocker for Linux (Ubuntu Target Host).

Monitors incoming traffic via raw AF_PACKET sockets, tracks packet ingress rates
per source IPv4 address across a configurable time window, and executes host-level
iptables DROP rules when volumetric thresholds are breached.
"""

import os
import sys
import time
import struct
import socket
import subprocess
from collections import defaultdict

# --- CONFIGURATION SETTINGS ---
PACKET_THRESHOLD = 150       # Maximum tolerated packets per source IP per time window
MONITOR_WINDOW = 1.0         # Sampling time window in seconds
WHITELIST_IPS = {
    "127.0.0.1",
    "192.168.1.1",          # pfSense LAN gateway IP
}

# --- TRACKING STRUCTURES ---
packet_counters = defaultdict(int)
blocked_ips = set()


def check_root_privileges():
    """Verify script is running with administrative privileges."""
    if os.geteuid() != 0:
        print("[!] Error: Root privileges required to open raw sockets and modify iptables.")
        print("[*] Please run the script with: sudo python3 dos_blocker.py")
        sys.exit(1)


def parse_ipv4_packet(raw_packet: bytes):
    """
    Extracts Layer 3 IPv4 header information.
    Layer 2 Ethernet header size is 14 bytes:
    - 6 bytes Dest MAC
    - 6 bytes Src MAC
    - 2 bytes EtherType (0x0800 for IPv4)
    """
    eth_header_len = 14
    if len(raw_packet) < eth_header_len + 20:
        return None, None

    # Unpack IPv4 header (20 bytes minimum)
    ipv4_header = raw_packet[eth_header_len:eth_header_len + 20]
    unpacked_header = struct.unpack('!BBHHHBBH4s4s', ipv4_header)

    protocol = unpacked_header[6]
    src_ip_bytes = unpacked_header[8]
    src_ip = socket.inet_ntoa(src_ip_bytes)

    return src_ip, protocol


def block_ip_address(ip: str):
    """Inserts a DROP rule at the top of the iptables INPUT chain."""
    if ip in blocked_ips or ip in WHITELIST_IPS:
        return

    print(f"\n[ALERT] Rate threshold exceeded! Offending IP: {ip}")
    print(f"[*] Applying host firewall mitigation: iptables -I INPUT -s {ip} -j DROP")

    cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    try:
        subprocess.run(cmd, check=True)
        blocked_ips.add(ip)
        print(f"[SUCCESS] Packets from {ip} are now dropped at kernel level.\n")
    except subprocess.CalledProcessError as error:
        print(f"[-] Execution error inserting iptables rule: {error}")


def main():
    check_root_privileges()

    # Create raw socket bound to Ethernet protocol (0x0800 = IPv4)
    try:
        raw_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0800))
    except Exception as err:
        print(f"[-] Socket creation failure: {err}")
        sys.exit(1)

    print("=" * 60)
    print("        Automated Layer-3/4 DoS Detection & Blocker         ")
    print("=" * 60)
    print(f"[*] Monitoring Active on raw socket interface...")
    print(f"[*] Threshold Configured: > {PACKET_THRESHOLD} packets / {MONITOR_WINDOW}s")
    print(f"[*] Whitelisted Addresses: {', '.join(WHITELIST_IPS)}")
    print("[*] Listening for ingress network floods (Press Ctrl+C to stop)...")

    window_start_time = time.time()

    try:
        while True:
            # Capture incoming frame (max MTU buffer 65535)
            packet_data, _ = raw_sock.recvfrom(65535)

            src_ip, _ = parse_ipv4_packet(packet_data)
            if src_ip and src_ip not in WHITELIST_IPS and src_ip not in blocked_ips:
                packet_counters[src_ip] += 1

            current_time = time.time()

            # Evaluate rolling threshold at each interval boundary
            if current_time - window_start_time >= MONITOR_WINDOW:
                for ip, count in list(packet_counters.items()):
                    if count > PACKET_THRESHOLD and ip not in blocked_ips:
                        print(f"[*] Ingress volumetric rate: {count} pkts/{MONITOR_WINDOW}s from {ip}")
                        block_ip_address(ip)

                # Reset bucket counts for next evaluation period
                packet_counters.clear()
                window_start_time = current_time

    except KeyboardInterrupt:
        print("\n\n[*] Monitoring terminated by user.")
        print(f"[*] Total malicious IPs mitigated this session: {len(blocked_ips)}")
        if blocked_ips:
            print("    Blocked addresses:")
            for b_ip in blocked_ips:
                print(f"    - {b_ip}")
            print("\n[*] Note: To clear blocked iptables rules later, run:")
            print("    sudo iptables -F INPUT")
        sys.exit(0)


if __name__ == "__main__":
    main()

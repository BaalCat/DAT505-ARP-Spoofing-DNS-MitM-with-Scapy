# DAT505 — ARP Spoofing & DNS MitM Lab

A collection of Python scripts demonstrating ARP cache poisoning and selective DNS spoofing in an isolated lab environment using Scapy.

## Overview

This project implements three main tools:

1. **arp_spoof.py** — Establishes a man-in-the-middle position by poisoning ARP caches of victim and gateway.
2. **traffic_interceptor.py** — Captures network traffic, saves protocol-specific PCAPs, and extracts URLs, DNS queries, top talkers, and protocol statistics.
3. **dns_spoof.py** — Intercepts and selectively spoofs DNS queries using whitelist/blacklist modes with optional upstream forwarding.
4. **HTTP_server.py** — Serves a fake web page on the attacker and logs all incoming requests.

## Requirements

See `requirements.txt` for Python package dependencies. System requirements:

- Linux (Ubuntu/Kali) with Python 3.7+
- Root privileges (for raw packet I/O and system configuration)
- VirtualBox or similar hypervisor (isolated internal network only)
- Network interface accessible to Scapy

Install dependencies:

```bash
sudo apt update
sudo apt install -y python3 python3-pip tcpdump wireshark
pip install -r requirements.txt
```

## Project Structure

```
.
├── arp_spoof.py                                       # ARP poisoning tool (Task 1)
├── traffic_interceptor.py                             # Traffic capture & parser (Task 2)
├── dns_spoof.py                                       # DNS spoofing tool (Task 3)
├── HTTP_server.py                                     # Fake web server (Task 3)
├── requirements.txt                                   # Python dependencies
├── README.md                                          # This file
├── Task3_whitelist_config_attacker.txt                # DNS whitelist config (domain,ip pairs)
├── Task3_blacklist_config_attacker.txt                # DNS blacklist config (exempted domains)
│
├── evidence/                                 # Task 2 extracted artifacts/images
│   ├── Task1_Arp_Table_Victim_after.png               # Screenshot of Victims ARP Table After poisoning
│   ├── Task1_Arp_Table_Victim_before.png              # Screenshot of Victims ARP Table before poisoning
│   ├── task2_urls.txt                                 # Extracted HTTP URLs from captured traffic
│   ├── task2_dns_queries.txt                          # Extracted DNS queries (qname, qtype, source IP)
│   ├── task2_dns_responses.txt                        # Extracted DNS responses (qname, rdata)
│   ├── task2_arp_replies.txt                          # Extracted ARP replies for spoofing detection
│   ├── task2_http_requests.txt                        # Full HTTP request payloads
│   ├── task2_http_responses.txt                       # HTTP response headers and bodies
│   ├── task2_top_talkers.csv                          # Top 20 source IPs by packet count
│   ├── task2_conversations.csv                        # Top 20 IP pairs by traffic volume
│   ├── task2_protocol_counts.txt                      # Protocol distribution (HTTP, DNS, ARP, etc.)
│   ├── Task2_wireshark_HTTP_request_captured_attacker.png  # Screenshot HTTP request in Wireshark
│   ├── Task3_attacker_spoof_web_server_log.log        # HTTP server access log showing victim requests
│   ├── Task3_victim_browser_cat.png                   # Screenshot Victim browser showing redirected "cat" domain
│   ├── Task3_victim_browser_gamer.png                 # Screenshot Victim browser showing redirected "gamer" domain
│   └── Task3_victim_browser_test.png                  # Screenshot Victim browser showing redirected "test" domain
│
└── pcap_files/                                # All PCAP captures
├── task1_arp_spoofing_attacker_during.pcap            # ARP and IP traffic captured on attacker
    ├── task1_arp_spoofing_victim_during.pcap          # Traffic captured on victim VM
    ├── task2_sniff_script_all_capture_attacker.pcap   # Full packet capture (all protocols)
    ├── task2_sniff_script_dns_attacker.pcap           # DNS protocol only
    ├── task2_sniff_script_http_attacker.pcap          # HTTP protocol only
    ├── task2_sniff_script_arp_attacker.pcap           # ARP protocol only
    ├── task2_sniff_script_icmp_attacker.pcap          # ICMP protocol only
    └── task3_attacker_mitm_DNS_Spoof.pcap             # DNS spoofing evidence capture
```

### Folder Descriptions

**Root directory (scripts & configs):**

- `arp_spoof.py` — Main ARP poisoning script; establishes MITM position
- `traffic_interceptor.py` — Packet sniffer and parser; creates protocol-specific PCAPs and extracts artifacts
- `dns_spoof.py` — DNS interceptor and spoofer; redirects queries based on whitelist/blacklist
- `HTTP_server.py` — Fake web server; serves attacker page and logs victim requests
- `Task3_whitelist_config_attacker.txt` — Configuration file listing domains to spoof (whitelist mode)
- `Task3_blacklist_config_attacker.txt` — Configuration file listing domains to exempt (blacklist mode)

**evidence/ folder:**

- **PNG screenshots:** Visual proof of ARP table changes, Wireshark captures, and victim browser redirects
- **Text extracts:** Parsed data from traffic_interceptor.py output (URLs, DNS queries, top talkers, etc.)
- **Log files:** HTTP server access logs showing victim requests to attacker's fake page

**pcap_files/ folder:**

- **Task 1 captures:** Raw ARP and IP traffic from attacker and victim during spoofing
- **Task 2 captures:** Full packet capture and per-protocol PCAPs (dns.pcap, http.pcap, arp.pcap, icmp.pcap)
- **Task 3 captures:** DNS spoofing evidence showing forged replies and victim traffic

## Task 1: ARP Spoofing (arp_spoof.py)

Poisons ARP caches to place attacker in-path between victim and gateway.

### Usage

```bash
sudo python3 arp_spoof.py -i eth0 -v 10.0.0.20 -g 10.0.0.1 --enable-ipfwd -t 2 -V
```

### Arguments

- `-i, --interface <iface>` — Network interface (e.g., eth0)
- `-v, --victim <ip>` — Victim IP address
- `-g, --gateway <ip>` — Gateway IP address
- `-t, --interval <seconds>` — ARP poison interval in seconds (default: 2.0, min: 0.1)
- `--enable-ipfwd` — Enable kernel IP forwarding (optional, for transparent MitM)
- `--disable-ipfwd` — Disable IP forwarding after poisoning (default if not specified)
- `-V, --verbose` — Verbose output

### Example

```bash
# Start poisoning with verbose output and IP forwarding enabled
sudo python3 arp_spoof.py -i eth0 -v 10.0.0.20 -g 10.0.0.1 --enable-ipfwd -V

# Stop with Ctrl+C (restores ARP caches automatically)
```

### Verification

Before/after screenshots of ARP tables (victim and gateway):

```bash
# Before attack
arp -n

# During attack (from victim)
arp -n
```

### Cleanup

The script automatically restores ARP entries on exit. Manual cleanup if needed:

```bash
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=1
```

---

## Task 2: Traffic Capture & Analysis (traffic_interceptor.py)

Sniffs network traffic, saves full and protocol-specific PCAPs, and extracts URLs, DNS queries, top talkers, and protocol counts.

### Usage

```bash
sudo python3 traffic_interceptor.py -i eth0 -t 120 -o capture.pcap --pcap-dir pcaps -v
```

### Arguments

- `-i, --interface <iface>` — Network interface to capture on (required)
- `-o, --out <file>` — Output main PCAP file (default: capture.pcap)
- `-t, --timeout <seconds>` — Capture duration in seconds (default: 60)
- `-c, --count <n>` — Packet count limit (if >0, overrides timeout)
- `-f, --filter <bpf>` — BPF filter (e.g., "port 53 or port 80")
- `--pcap-dir <dir>` — Directory for protocol-specific PCAPs (default: captures_pcap)
- `-v, --verbose` — Verbose output

### Example

```bash
# Capture for 120 seconds, write full PCAP and protocol-specific PCAPs
sudo python3 traffic_interceptor.py -i eth0 -t 120 -o task2_capture.pcap --pcap-dir task2_pcap -v

# Capture DNS+HTTP only (BPF filter) for 60 seconds
sudo python3 traffic_interceptor.py -i eth0 -t 60 -f "port 53 or port 80" --pcap-dir task2_pcap

# Capture first 1000 packets
sudo python3 traffic_interceptor.py -i eth0 -c 1000 -o capture_1k.pcap --pcap-dir pcaps
```

### Outputs

**Main PCAP:** `capture.pcap` (or specified with `-o`)

**Protocol-specific PCAPs** (in `captures_pcap/` or `--pcap-dir`):

- `dns.pcap`, `http.pcap`, `https.pcap`, `ssh.pcap`, `ftp.pcap`, `arp.pcap`, `icmp.pcap`, `dhcp.pcap`, `ntp.pcap`, etc.

**Text extracts** (in `captures_out/`):

- `urls.txt` — HTTP requests (method, URL, timestamp)
- `dns_queries.txt` — DNS queries (qname, qtype, source IP)
- `dns_responses.txt` — DNS responses (qname, rdata)
- `arp_replies.txt` — ARP replies (useful for spoofing detection)
- `http_requests.txt` — Full HTTP request payloads
- `http_responses.txt` — HTTP response headers
- `ftp_credentials.txt` — Captured FTP commands (USER/PASS)
- `top_talkers.csv` — Top 20 source IPs by packet count
- `conversations.csv` — Top 20 IP pairs by traffic volume
- `protocol_counts.txt` — Protocol distribution

### View Outputs

```bash
# List protocol-specific PCAPs
ls -lh captures_pcap/

# View extracted URLs
cat captures_out/urls.txt

# View top talkers
cat captures_out/top_talkers.csv

# Open PCAP in Wireshark
wireshark captures_pcap/dns.pcap &
```

---

## Task 3: DNS Spoofing (dns_spoof.py)

Intercepts and selectively spoofs DNS queries using whitelist or blacklist modes.

### Usage

```bash
# Whitelist mode (only spoof listed domains)
sudo python3 dns_spoof.py -i eth0 -c whitelist.txt -m whitelist -u 10.0.0.1 -w 8 -v

# Blacklist mode (spoof all except exempted domains)
sudo python3 dns_spoof.py -i eth0 -c exemptions.txt -m blacklist --default-ip 10.0.0.10 -u 10.0.0.1 -w 8 -v
```

### Arguments

- `-i, --interface <iface>` — Network interface to sniff on (required)
- `-c, --config <file>` — Configuration file (required)
  - Whitelist: `domain,ip` per line (e.g., `www.test.no,10.0.0.10`)
  - Blacklist: `domain` per line (exemptions; no IP needed)
- `-m, --mode <mode>` — Mode: `whitelist` or `blacklist` (default: whitelist)
- `--default-ip <ip>` — Default IP for blacklist mode (required in blacklist mode)
- `-u, --upstream <ip>` — Upstream DNS server for forwarding non-targeted queries (recommended)
- `-w, --workers <n>` — Number of worker threads (default: 4)
- `-v, --verbose` — Verbose output

### Configuration Files

**Whitelist mode** (`whitelist.txt`):

```
# Comments start with #
www.test.no,10.0.0.10
example.com,10.0.0.10
mail.example.com,10.0.0.10
```

**Blacklist mode** (`exemptions.txt`):

```
# These domains will NOT be spoofed
internal.example.com
trusted.service.net
```

### Examples

```bash
# Whitelist: only spoof domains in whitelist.txt, forward others to 10.0.0.1
sudo python3 dns_spoof.py -i eth0 -c whitelist.txt -m whitelist -u 10.0.0.1 -w 8 -v

# Blacklist: spoof all to 10.0.0.10 except domains in exemptions.txt
sudo python3 dns_spoof.py -i eth0 -c exemptions.txt -m blacklist --default-ip 10.0.0.10 -u 10.0.0.1 -w 8 -v
```

### Performance Tuning

- Start with 4–8 workers; increase if you see lag under heavy DNS traffic
- Reduce upstream timeout (default 0.8s) if DNS server is fast
- Disable verbose mode during production testing to reduce overhead

### Cleanup & Restore

```bash
# Remove iptables rules (if added during testing)
sudo iptables -D FORWARD -s <VICTIM_IP> -p udp --dport 53 -j DROP
sudo iptables -D FORWARD -s <VICTIM_IP> -p tcp --dport 53 -j DROP

# Disable IP forwarding if enabled
sudo sysctl -w net.ipv4.ip_forward=0

# Restore ICMP redirects
sudo sysctl -w net.ipv4.conf.all.send_redirects=1
sudo sysctl -w net.ipv4.conf.all.accept_redirects=1
```

---

## Task 3: Fake HTTP Server (HTTP_server.py)

Serves a fake web page and logs all incoming requests. Automatically generates a default landing page if none exists.

### Usage

```bash
sudo python3 HTTP_server.py --port 80 --log-dir ./logs --www-dir ./www
```

### Arguments

- `--host <ip>` — IP to bind to (default: 0.0.0.0 = all interfaces)
- `--port <port>` — HTTP server port (default: 80, requires root for ports <1024)
- `--log-dir <dir>` — Directory for access logs (default: ./logs)
- `--www-dir <dir>` — Directory to serve files from (default: ./www)

### Example

```bash
# Start on port 80 with default fake landing page
sudo python3 HTTP_server.py --port 80 --log-dir ./logs --www-dir ./www

# View access log showing victim requests
cat logs/access.log

# Serve custom content from a different directory
sudo python3 HTTP_server.py --port 80 --www-dir /path/to/custom/site
```

### Default Behavior

If no `index.html` exists in `--www-dir`, the server automatically generates a convincing fake landing page with:

- Prominent "DNS Spoofed" warning message
- Victim redirect notification
- Security alert styling
- Request logging with timestamp, client IP, HTTP method, path, response code, User-Agent

All requests are logged to `--log-dir/access.log` with:

- Timestamp, client IP, HTTP method, request path, response code, Host header, User-Agent

---

## Complete Lab Workflow

### Step 1: Setup Environment

```bash
# On Attacker VM:
# Disable ICMP redirects
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0

# Drop forwarded DNS (so DNS spoof wins)
sudo iptables -I FORWARD -s 10.0.0.20 -p udp --dport 53 -j DROP
sudo iptables -I FORWARD -s 10.0.0.20 -p tcp --dport 53 -j DROP
```

### Step 2: Run ARP Spoof (Terminal 1)

```bash
sudo python3 arp_spoof.py -i eth0 -v 10.0.0.20 -g 10.0.0.1 --enable-ipfwd -V
```

### Step 3: Start Traffic Capture (Terminal 2)

```bash
sudo python3 traffic_interceptor.py -i eth0 -t 120 -o task_capture.pcap --pcap-dir task_pcaps -v
```

### Step 4: Start DNS Spoof (Terminal 3)

```bash
sudo python3 dns_spoof.py -i eth0 -c whitelist.txt -m whitelist -u 10.0.0.1 -w 8 -v
```

### Step 5: Start Fake HTTP Server (Terminal 4)

```bash
sudo python3 HTTP_server.py --port 80 --log-dir ./logs --www-dir ./www
```

### Step 6: Generate Traffic (Victim VM)

```bash
# DNS lookup
dig www.test.no

# Open browser and visit spoofed domain
firefox http://www.test.no
```

### Step 7: Collect Evidence

```bash
# Stop all scripts with Ctrl+C
# Review captures
ls -lh *.pcap task_pcaps/
ls -lh captures_out/

# View HTTP server logs
cat logs/access.log

# View extracted URLs/DNS queries
cat captures_out/urls.txt
cat captures_out/dns_queries.txt
```

---

## Troubleshooting

**DNS queries timeout on victim**

- Increase worker threads: `-w 16`
- Check iptables DROP rules are in place
- Reduce upstream timeout in `dns_spoof.py`

**ARP spoof not working**

- Verify victim/gateway IPs are correct
- Ensure interface is correct (`ip addr show`)
- Check kernel forwarding is enabled if needed
- Disable NetworkManager interference

**HTTP server not receiving requests**

- Verify DNS spoof is working (check dns_spoof.py verbose output)
- Confirm port 80 is not already in use: `sudo lsof -i :80`
- Check victim is on the same network segment

**High I/O load during capture**

- Use BPF filter to limit traffic: `-f "port 53 or port 80"`
- Reduce verbose logging
- Write to faster storage (SSD/RAM disk)

---

## Ethics & Legal Disclaimer

**IMPORTANT:** All tools in this project are designed **exclusively for educational purposes in isolated laboratory environments**. Use of these tools is **strictly limited to**:

- Isolated virtual networks (VirtualBox, VMware, etc.) that you control
- Closed lab environments with explicit authorization
- Educational coursework (DAT505 or equivalent)

**PROHIBITED USES:**

- Unauthorized network testing on university, corporate, or public networks
- Intercepting traffic from systems you do not own or have explicit written permission to test
- Disrupting network services or attacking production systems
- Any use that violates local, national, or international laws

**Legal Consequences:**

Unauthorized use of these tools may result in:

- Criminal prosecution under laws such as the Computer Fraud and Abuse Act (CFAA) or equivalent
- Civil liability for damages
- University disciplinary action (expulsion, suspension)
- Employment termination and blacklisting

**By using these scripts, you acknowledge:**

- You will only use them in authorized, isolated environments
- You accept full legal responsibility for any misuse
- You understand the ethical implications and potential harm
- You agree to comply with all applicable laws and regulations

**If you are unsure whether your use is authorized, DO NOT use these tools. Ask your instructor or lab supervisor first.**

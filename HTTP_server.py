#!/usr/bin/env python3
"""
Fake HTTP Server — DAT505 Lab Tool
Simple HTTP server with request logging for DNS spoof redirection demo.
Automatically binds to all interfaces and serves a fake landing page.
"""
import os
import sys
import argparse
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from datetime import datetime

class LoggingHandler(SimpleHTTPRequestHandler):
    """Custom handler that logs all requests with timestamps and client info."""
    
    def log_request(self, code='-', size='-'):
        """Override to write structured logs to file and console."""
        host_hdr = self.headers.get('Host', '-')
        ua = self.headers.get('User-Agent', '-')
        timestamp = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')
        line = f"{timestamp}\t{self.client_address[0]}\t{self.command}\t{self.path}\t{code}\t{size}\t{host_hdr}\t{ua}"
        
        # Write to log file
        log_path = os.path.join(self.server.log_dir, "access.log")
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")
        
        # Print to console
        print(f"[+] {line}")

    def end_headers(self):
        """Add headers to prevent caching (helps with testing/demos)."""
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Expires', '0')
        super().end_headers()

def setup_fake_site(www_dir):
    """Create a convincing fake landing page if index.html doesn't exist."""
    os.makedirs(www_dir, exist_ok=True)
    index_path = os.path.join(www_dir, "index.html")
    
    if not os.path.isfile(index_path):
        html_content = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Welcome</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 0;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            color: white;
        }
        .container {
            text-align: center;
            background: rgba(0,0,0,0.3);
            padding: 60px 40px;
            border-radius: 20px;
            box-shadow: 0 8px 32px rgba(0,0,0,0.3);
            backdrop-filter: blur(10px);
        }
        h1 {
            font-size: 3em;
            margin: 0 0 20px 0;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.5);
        }
        p {
            font-size: 1.2em;
            margin: 10px 0;
        }
        .warning {
            background: rgba(255,0,0,0.2);
            border: 2px solid rgba(255,0,0,0.5);
            padding: 20px;
            margin-top: 30px;
            border-radius: 10px;
        }
        code {
            background: rgba(0,0,0,0.3);
            padding: 2px 8px;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>⚠️ DNS Spoofed</h1>
        <p>You have been redirected by a DNS spoofing attack.</p>
        <p>This is a demonstration for <strong>DAT505 Lab Assignment</strong>.</p>
        <div class="warning">
            <strong>Security Notice:</strong><br>
            Your DNS queries have been intercepted and redirected to this attacker-controlled server.
            <br><br>
            <code>Original request was redirected here</code>
        </div>
        <p style="margin-top: 30px; font-size: 0.9em; opacity: 0.8;">
            Server: fake_http_server.py | Lab Environment Only
        </p>
    </div>
</body>
</html>"""
        with open(index_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        print(f"[*] Created fake landing page: {index_path}")

def run_server(host, port, www_dir, log_dir):
    """Start the HTTP server with logging."""
    # Resolve absolute paths
    www_dir = os.path.abspath(www_dir)
    log_dir = os.path.abspath(log_dir)
    
    # Setup directories and fake site
    os.makedirs(log_dir, exist_ok=True)
    setup_fake_site(www_dir)
    
    # Change to www directory so SimpleHTTPRequestHandler serves from there
    original_dir = os.getcwd()
    os.chdir(www_dir)
    
    try:
        # Create server
        server = ThreadingHTTPServer((host, port), LoggingHandler)
        server.log_dir = log_dir
        
        # Get actual bind address
        actual_host = server.server_address[0]
        actual_port = server.server_address[1]
        
        print(f"[*] Fake HTTP Server Started")
        print(f"[*] Serving: {www_dir}")
        print(f"[*] Logs: {log_dir}/access.log")
        print(f"[*] Listening on: http://{actual_host}:{actual_port}")
        if actual_host == "0.0.0.0":
            print(f"[*] Access from victim using attacker's IP (e.g., http://10.0.0.10)")
        print(f"[*] Press Ctrl+C to stop")
        print("-" * 60)
        
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Server stopped by user")
    except PermissionError:
        print(f"[!] Permission denied. Need sudo to bind port {port} (ports <1024 require root)")
        sys.exit(1)
    except OSError as e:
        if "Cannot assign requested address" in str(e):
            print(f"[!] Cannot bind to {host}. IP not configured on any interface.")
            print(f"[*] Try using --host 0.0.0.0 to listen on all interfaces")
            print(f"[*] Or add the IP: sudo ip addr add {host}/24 dev <interface>")
        else:
            print(f"[!] Error: {e}")
        sys.exit(1)
    finally:
        os.chdir(original_dir)
        if 'server' in locals():
            server.server_close()

def main():
    parser = argparse.ArgumentParser(
        description="Fake HTTP server for DNS spoof demonstration (DAT505 Lab)"
    )
    parser.add_argument("--host", default="0.0.0.0", 
                        help="IP to bind (default: 0.0.0.0 = all interfaces)")
    parser.add_argument("--port", type=int, default=80,
                        help="Port to listen on (default: 80, requires sudo)")
    parser.add_argument("--www-dir", default="www",
                        help="Directory to serve files from (default: ./www)")
    parser.add_argument("--log-dir", default="logs",
                        help="Directory for access logs (default: ./logs)")
    args = parser.parse_args()
    
    # Check if running as root for port 80
    if args.port < 1024 and os.geteuid() != 0:
        print(f"[!] Port {args.port} requires root privileges. Run with sudo.")
        sys.exit(1)
    
    run_server(args.host, args.port, args.www_dir, args.log_dir)

if __name__ == "__main__":
    main()
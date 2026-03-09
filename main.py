#!/usr/bin/env python3
"""
ReconTool — Subdomain + Port + Directory Scanner
For educational use on authorized targets (TryHackMe, HackTheBox, etc.)

Usage examples:
  Full scan:
    python main.py -t 10.10.10.5 --all

  Subdomain only:
    python main.py -t example.com --subdomains

  Port scan with full range:
    python main.py -t 10.10.10.5 --ports --port-range 1-65535

  Directory scan on custom port:
    python main.py -t 10.10.10.5 --dirs --web-port 8080

  Combined:
    python main.py -t 10.10.10.5 --ports --dirs --no-nmap
"""

import argparse
import sys
import os
from datetime import datetime

# Make sure we can import from sibling directories
sys.path.insert(0, os.path.dirname(__file__))

from utils.output import (
    print_banner, print_info, print_error, print_warn,
    print_section, print_summary, save_results
)
import modules.subdomain as subdomain_module
import modules.portscan as portscan_module
import modules.dirscan as dirscan_module


# ─── Default Wordlists (bundled with tool) ────────────────────────────────
DEFAULT_SUBDOMAINS_WORDLIST = "wordlists/subdomains.txt"
DEFAULT_DIRS_WORDLIST       = "wordlists/directories.txt"


def parse_args():
    parser = argparse.ArgumentParser(
        description="ReconTool — Educational Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    # ── Target ──
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target domain or IP (e.g. 10.10.10.5 or example.com)"
    )

    # ── Scan Modules ──
    parser.add_argument("--all",        action="store_true", help="Run ALL modules")
    parser.add_argument("--subdomains", action="store_true", help="Run subdomain enumeration")
    parser.add_argument("--ports",      action="store_true", help="Run port scanning")
    parser.add_argument("--dirs",       action="store_true", help="Run directory discovery")

    # ── Subdomain Options ──
    sub = parser.add_argument_group("Subdomain Options")
    sub.add_argument("--sub-wordlist", default=DEFAULT_SUBDOMAINS_WORDLIST,
                     help=f"Subdomain wordlist (default: {DEFAULT_SUBDOMAINS_WORDLIST})")
    sub.add_argument("--no-passive", action="store_true",
                     help="Skip crt.sh passive recon")
    sub.add_argument("--sub-threads", type=int, default=50,
                     help="Threads for subdomain brute-force (default: 50)")

    # ── Port Scan Options ──
    port = parser.add_argument_group("Port Scan Options")
    port.add_argument("--port-range", default=None,
                      help="Port range e.g. 1-1000 or specific ports: 22,80,443")
    port.add_argument("--port-threads", type=int, default=100,
                      help="Threads for port scanning (default: 100)")
    port.add_argument("--no-nmap", action="store_true",
                      help="Skip nmap service detection (faster, less info)")

    # ── Directory Scan Options ──
    dirs = parser.add_argument_group("Directory Scan Options")
    dirs.add_argument("--dir-wordlist", default=DEFAULT_DIRS_WORDLIST,
                      help=f"Directory wordlist (default: {DEFAULT_DIRS_WORDLIST})")
    dirs.add_argument("--web-port", type=int, default=80,
                      help="Web server port (default: 80)")
    dirs.add_argument("--https", action="store_true",
                      help="Use HTTPS instead of HTTP")
    dirs.add_argument("--dir-threads", type=int, default=50,
                      help="Concurrent requests for dir scan (default: 50)")
    dirs.add_argument("--extensions", default=None,
                      help="Comma-separated file extensions: .php,.txt,.bak")

    # ── Output ──
    out = parser.add_argument_group("Output Options")
    out.add_argument("-o", "--output", default="results",
                     help="Output directory for reports (default: results/)")
    out.add_argument("--no-save", action="store_true",
                     help="Don't save results to file")

    return parser.parse_args()


def parse_ports(port_range_str: str) -> list[int]:
    """Parse --port-range argument: supports ranges (1-1000) and lists (22,80,443)"""
    ports = []
    for part in port_range_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))


def main():
    print_banner()
    args = parse_args()

    # If --all, enable all modules
    if args.all:
        args.subdomains = True
        args.ports = True
        args.dirs = True

    # Must select at least one module
    if not any([args.subdomains, args.ports, args.dirs]):
        print_error("No module selected! Use --subdomains, --ports, --dirs, or --all")
        print_info("Run with --help for usage examples.")
        sys.exit(1)

    target = args.target.strip()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print_info(f"Target  : {target}")
    print_info(f"Started : {timestamp}")
    print_warn("REMINDER: Only scan targets you are authorized to test!")
    print()

    # ── Aggregate Results ────────────────────────────────────────────────
    results = {
        "target": target,
        "timestamp": timestamp,
        "subdomains": [],
        "ports": {},
        "directories": [],
    }

    # ── Module 1: Subdomain Enumeration ─────────────────────────────────
    if args.subdomains:
        print_section("🌐 MODULE 1: SUBDOMAIN ENUMERATION")
        results["subdomains"] = subdomain_module.run(
            domain=target,
            wordlist=args.sub_wordlist,
            threads=args.sub_threads,
            passive=not args.no_passive,
        )
        print_info(f"Total subdomains found: {len(results['subdomains'])}")

    # ── Module 2: Port & Service Scanning ────────────────────────────────
    if args.ports:
        print_section("🔌 MODULE 2: PORT & SERVICE SCANNING")

        ports = None
        if args.port_range:
            try:
                ports = parse_ports(args.port_range)
                print_info(f"Scanning {len(ports)} specified ports.")
            except ValueError:
                print_error(f"Invalid port range: {args.port_range}")
                sys.exit(1)

        results["ports"] = portscan_module.run(
            host=target,
            ports=ports,
            threads=args.port_threads,
            deep=not args.no_nmap,
        )
        print_info(f"Open ports found: {results['ports'].get('open_ports', [])}")

    # ── Module 3: Directory Discovery ────────────────────────────────────
    if args.dirs:
        print_section("📁 MODULE 3: DIRECTORY & FILE DISCOVERY")

        extensions = None
        if args.extensions:
            extensions = [e.strip() for e in args.extensions.split(",")]

        # Auto-detect HTTPS from port
        use_https = args.https or args.web_port == 443

        results["directories"] = dirscan_module.run(
            target=target,
            wordlist_path=args.dir_wordlist,
            port=args.web_port,
            use_https=use_https,
            extensions=extensions,
            concurrency=args.dir_threads,
        )
        print_info(f"Paths/files found: {len(results['directories'])}")

    # ── Summary & Save ────────────────────────────────────────────────────
    print_summary(results)

    if not args.no_save:
        save_results(results, output_dir=args.output)

    print_info("Scan complete. Happy hacking (ethically)! 🎯")


if __name__ == "__main__":
    main()
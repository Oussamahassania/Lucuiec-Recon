#!/usr/bin/env python3
"""
ReconTool v2.0 — Advanced Bug Bounty Recon Framework
For authorized security testing on TryHackMe, HackTheBox, and permitted targets.

MODULES:
  1. Subdomain Enumeration    — DNS brute-force + crt.sh passive recon
  2. Port & Service Scanning  — TCP scan + nmap version detection
  3. Directory Discovery      — Async HTTP brute-force
  4. Technology Fingerprint   — Server/framework/WAF/CMS detection
  5. CVE Correlation          — Auto NVD lookup for detected service versions
  6. JS File Mining           — Extract secrets/endpoints from JavaScript
  7. Sensitive File Hunter    — .env, backups, git, keys, configs
  8. Parameter Discovery      — Hidden GET/POST parameter detection
  9. HTML Report              — Professional color-coded report

EXAMPLES:
  Full offensive scan:
    python main.py -t 10.10.10.5 --all

  Web-focused (fingerprint + JS + sensitive files + params):
    python main.py -t 10.10.10.5 --fingerprint --js --sensitive --params

  Port scan + CVE lookup:
    python main.py -t 10.10.10.5 --ports --cve

  Custom ports + web scan:
    python main.py -t 10.10.10.5 --ports --port-range 1-10000 --dirs --web-port 8080

  Quick scan (no nmap, no CVE):
    python main.py -t 10.10.10.5 --ports --dirs --no-nmap --no-cve
"""

import argparse
import socket
import subprocess
import sys
import os
from datetime import datetime

sys.path.insert(0, os.path.dirname(__file__))

from utils.output import (
    print_banner, print_info, print_error, print_warn,
    print_section, print_summary, save_results
)
from utils.html_report import save_html_report

import modules.subdomain       as subdomain_module
import modules.portscan        as portscan_module
import modules.dirscan         as dirscan_module
import modules.fingerprint     as fingerprint_module
import modules.cve_lookup      as cve_module
import modules.js_miner        as js_module
import modules.sensitive_files as sensitive_module
import modules.param_discovery as param_module
import modules.vhost_fuzzer    as vhost_module
import modules.cors_scanner    as cors_module
import modules.crawler         as crawler_module
import modules.wayback         as wayback_module
import modules.api_fuzzer      as api_module
import modules.vuln_scanner    as vuln_module


_HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SUBDOMAINS_WORDLIST = os.path.join(_HERE, "wordlists", "subdomains.txt")
DEFAULT_DIRS_WORDLIST       = os.path.join(_HERE, "wordlists", "directories.txt")


def parse_args():
    parser = argparse.ArgumentParser(
        description="ReconTool v3.0 — Ultimate Web Hacking Recon Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Target ──────────────────────────────────────────────────────────────
    parser.add_argument("-t", "--target", required=True,
                        help="Target domain or IP (e.g. 10.10.10.5 or example.com)")

    # ── Module Selection ─────────────────────────────────────────────────────
    mods = parser.add_argument_group("Scan Modules")
    mods.add_argument("--all",         action="store_true", help="Run ALL modules")
    mods.add_argument("--subdomains",  action="store_true", help="Subdomain enumeration")
    mods.add_argument("--ports",       action="store_true", help="Port + service scanning")
    mods.add_argument("--dirs",        action="store_true", help="Directory discovery")
    mods.add_argument("--fingerprint", action="store_true", help="Technology fingerprinting")
    mods.add_argument("--cve",         action="store_true", help="CVE correlation (requires --ports)")
    mods.add_argument("--js",          action="store_true", help="JavaScript file mining")
    mods.add_argument("--sensitive",   action="store_true", help="Sensitive file hunter")
    mods.add_argument("--params",      action="store_true", help="Hidden parameter discovery")
    mods.add_argument("--vhost",       action="store_true", help="Virtual host fuzzing")
    mods.add_argument("--cors",        action="store_true", help="CORS misconfiguration scanner")
    mods.add_argument("--crawl",       action="store_true", help="Web crawler + URL finder")
    mods.add_argument("--wayback",     action="store_true", help="Wayback Machine historical URLs")
    mods.add_argument("--api",         action="store_true", help="API endpoint fuzzer")
    mods.add_argument("--vulns",       action="store_true", help="Vulnerability scanner (SQLi/XSS/LFI/Redirect)")

    # ── Subdomain Options ────────────────────────────────────────────────────
    sub = parser.add_argument_group("Subdomain Options")
    sub.add_argument("--sub-wordlist", default=DEFAULT_SUBDOMAINS_WORDLIST)
    sub.add_argument("--no-passive",   action="store_true", help="Skip crt.sh")
    sub.add_argument("--sub-threads",  type=int, default=50)

    # ── Port Options ──────────────────────────────────────────────────────────
    port = parser.add_argument_group("Port Scan Options")
    port.add_argument("--port-range",   default=None, help="e.g. 1-1000 or 22,80,443")
    port.add_argument("--port-threads", type=int, default=100)
    port.add_argument("--no-nmap",      action="store_true", help="Skip nmap service detection")
    port.add_argument("--no-cve",       action="store_true", help="Skip CVE lookup after port scan")

    # ── Web Options (shared by dirs/js/sensitive/params/fingerprint) ──────────
    web = parser.add_argument_group("Web Options (dirs, js, sensitive, params, fingerprint)")
    web.add_argument("--web-port",    type=int, default=80)
    web.add_argument("--https",       action="store_true")
    web.add_argument("--dir-wordlist", default=DEFAULT_DIRS_WORDLIST)
    web.add_argument("--dir-threads",  type=int, default=150, help="Concurrent requests (default 150)")
    web.add_argument("--extensions",   default=None, help="e.g. .php,.txt,.bak")
    web.add_argument("--recursive",    action="store_true", help="Recursive dir scan (like dirbuster -r)")
    web.add_argument("--depth",        type=int, default=3, help="Recursion depth (default 3)")
    web.add_argument("--base-path",    default="", help="Start scan from path e.g. /admin or /api/v1")
    web.add_argument("--param-paths",  default="/", help="Paths for param discovery, comma-separated")
    web.add_argument("--vhost-domain", default="",  help="Base domain for vhost fuzzing (e.g. target.com)")
    web.add_argument("--crawl-depth",  type=int, default=3, help="Crawler depth (default: 3)")
    web.add_argument("--no-alive-check", action="store_true", help="Skip Wayback alive URL check")

    # ── Output ────────────────────────────────────────────────────────────────
    out = parser.add_argument_group("Output Options")
    out.add_argument("-o", "--output", default="results")
    out.add_argument("--no-save",      action="store_true", help="Don't save reports")
    out.add_argument("--no-html",      action="store_true", help="Skip HTML report generation")
    out.add_argument("--force",        action="store_true", help="Skip connectivity check (use if target blocks all probes)")

    return parser.parse_args()


def parse_ports(port_range_str: str) -> list[int]:
    ports = []
    for part in port_range_str.split(","):
        part = part.strip()
        if "-" in part:
            start, end = part.split("-", 1)
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return sorted(set(ports))



def check_connectivity(target: str, timeout: int = 5) -> bool:
    """
    Check if the target is reachable before starting the scan.
    Tries TCP connect on common ports + ICMP ping.
    If nothing responds within timeout, warn and abort.
    """
    from utils.output import print_info, print_error, print_warn
    from colorama import Fore, Style

    print_info(f"Checking connectivity to {target}...")

    # Step 1: DNS resolution check (for domain targets)
    ip = target
    if not target.replace(".", "").isdigit():
        try:
            ip = socket.gethostbyname(target)
            print_info(f"Resolved {target} → {ip}")
        except socket.gaierror:
            print_error(f"Cannot resolve hostname: {target}")
            print_warn("Possible causes:")
            print_warn("  • You are not connected to VPN (TryHackMe/HackTheBox)")
            print_warn("  • The domain does not exist")
            print_warn("  • DNS is blocked on your network")
            return False

    # Step 2: Try TCP connect on common ports
    probe_ports = [80, 443, 22, 21, 8080, 8443, 3389]
    for port in probe_ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                print_info(f"Target is reachable (port {port} responded) ✅")
                return True
        except Exception:
            continue

    # Step 3: Try ICMP ping as last resort
    try:
        ping_cmd = ["ping", "-c", "1", "-W", str(timeout), ip]
        result = subprocess.run(ping_cmd, capture_output=True, timeout=timeout + 2)
        if result.returncode == 0:
            print_info(f"Target is reachable (ping responded) ✅")
            return True
    except Exception:
        pass

    # Nothing responded
    print_error(f"\n  Target {target} ({ip}) is NOT reachable!")
    print()
    print(f"  {Fore.YELLOW}Possible causes:{Style.RESET_ALL}")
    print(f"  {Fore.RED}  ❌ VPN not connected{Style.RESET_ALL} — Did you activate OpenVPN for TryHackMe/HackTheBox?")
    print(f"  {Fore.RED}  ❌ Wrong IP address{Style.RESET_ALL} — Double check the target IP in the platform")
    print(f"  {Fore.RED}  ❌ Target machine is off{Style.RESET_ALL} — Start/reset the machine on the platform")
    print(f"  {Fore.RED}  ❌ Firewall blocking{Style.RESET_ALL} — Target may block all probes (try --force to skip this check)")
    print()
    print(f"  {Fore.CYAN}TryHackMe VPN:{Style.RESET_ALL}  sudo openvpn ~/Downloads/your-vpn-file.ovpn")
    print(f"  {Fore.CYAN}HackTheBox VPN:{Style.RESET_ALL} sudo openvpn ~/Downloads/lab_username.ovpn")
    print()
    return False

def main():
    print_banner()
    args = parse_args()

    # --all enables everything
    if args.all:
        args.subdomains = args.ports = args.dirs = True
        args.fingerprint = args.js = args.sensitive = args.params = True
        args.vhost = args.cors = args.crawl = args.wayback = args.api = args.vulns = True
        # CVE runs automatically after ports unless --no-cve

    if not any([
        args.subdomains, args.ports, args.dirs, args.fingerprint,
        args.js, args.sensitive, args.params, args.cve,
        args.vhost, args.cors, args.crawl,
        args.wayback, args.api, args.vulns,
    ]):
        print_error("No module selected! Use --all or pick modules. Run --help for examples.")
        sys.exit(1)

    target    = args.target.strip()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    use_https = args.https or args.web_port == 443

    print_info(f"Target   : {target}")
    print_info(f"Started  : {timestamp}")
    print_info(f"Web port : {args.web_port} ({'HTTPS' if use_https else 'HTTP'})")
    print_warn("REMINDER : Only scan targets you are authorized to test!\n")

    # ── CONNECTIVITY CHECK ────────────────────────────────────────────────────
    if not args.force:
        if not check_connectivity(target):
            print_error("Scan aborted. Fix connectivity and try again.")
            print_warn("Use --force to skip this check (not recommended).")
            sys.exit(1)
        print()

    results = {
        "target":         target,
        "timestamp":      timestamp,
        "subdomains":     [],
        "ports":          {},
        "directories":    [],
        "technology":     {},
        "js_mining":      {},
        "sensitive_files":[],
        "parameters":     [],
        "vhosts":         [],
        "cors":           [],
        "crawl":          {},
        "wayback":        {},
        "api":            {},
        "vulnerabilities":{},
    }

    # ── 1. SUBDOMAIN ENUMERATION ─────────────────────────────────────────────
    if args.subdomains:
        print_section("🌐 MODULE 1: SUBDOMAIN ENUMERATION")
        results["subdomains"] = subdomain_module.run(
            domain=target,
            wordlist=args.sub_wordlist,
            threads=args.sub_threads,
            passive=not args.no_passive,
        )
        print_info(f"Subdomains found: {len(results['subdomains'])}")

    # ── 2. PORT & SERVICE SCANNING ───────────────────────────────────────────
    if args.ports:
        print_section("🔌 MODULE 2: PORT & SERVICE SCANNING")
        ports = None
        if args.port_range:
            try:
                ports = parse_ports(args.port_range)
                print_info(f"Scanning {len(ports)} ports.")
            except ValueError:
                print_error(f"Invalid port range: {args.port_range}")
                sys.exit(1)

        results["ports"] = portscan_module.run(
            host=target,
            ports=ports,
            threads=args.port_threads,
            deep=not args.no_nmap,
        )
        print_info(f"Open ports: {results['ports'].get('open_ports', [])}")

    # ── 3. CVE CORRELATION ───────────────────────────────────────────────────
    run_cve = (args.cve or (args.ports and not args.no_cve))
    if run_cve:
        print_section("🔴 MODULE 3: CVE CORRELATION")
        services = results["ports"].get("services", [])
        if services:
            enriched = cve_module.run(services)
            results["ports"]["services"] = enriched
        else:
            print_warn("No service data for CVE lookup. Run --ports without --no-nmap first.")

    # ── 4. TECHNOLOGY FINGERPRINTING ─────────────────────────────────────────
    if args.fingerprint:
        print_section("🖥️  MODULE 4: TECHNOLOGY FINGERPRINTING")
        results["technology"] = fingerprint_module.run(
            target=target,
            port=args.web_port,
            use_https=use_https,
        )

    # ── 5. DIRECTORY DISCOVERY ───────────────────────────────────────────────
    if args.dirs:
        print_section("📁 MODULE 5: DIRECTORY DISCOVERY")
        extensions = None
        if args.extensions:
            extensions = [e.strip() for e in args.extensions.split(",")]

        results["directories"] = dirscan_module.run(
            target=target,
            wordlist_path=args.dir_wordlist,
            port=args.web_port,
            use_https=use_https,
            extensions=extensions,
            concurrency=args.dir_threads,
            recursive=args.recursive,
            max_depth=args.depth,
            base_path=args.base_path,
        )
        print_info(f"Directories/files found: {len(results['directories'])}")

    # ── 6. SENSITIVE FILE HUNTER ─────────────────────────────────────────────
    if args.sensitive:
        print_section("🔑 MODULE 6: SENSITIVE FILE HUNTER")
        results["sensitive_files"] = sensitive_module.run(
            target=target,
            port=args.web_port,
            use_https=use_https,
        )

    # ── 7. JAVASCRIPT MINING ─────────────────────────────────────────────────
    if args.js:
        print_section("⚙️  MODULE 7: JAVASCRIPT FILE MINING")
        results["js_mining"] = js_module.run(
            target=target,
            port=args.web_port,
            use_https=use_https,
        )

    # ── 8. PARAMETER DISCOVERY ───────────────────────────────────────────────
    if args.params:
        print_section("🎯 MODULE 8: PARAMETER DISCOVERY")
        paths = [p.strip() for p in args.param_paths.split(",")]
        results["parameters"] = param_module.run(
            target=target,
            paths=paths,
            port=args.web_port,
            use_https=use_https,
        )

    # ── SUMMARY & SAVE ────────────────────────────────────────────────────────
    print_summary(results)

    if not args.no_save:
        save_results(results, output_dir=args.output)
        if not args.no_html:
            html_path = save_html_report(results, output_dir=args.output)
            from utils.output import print_found
            print_found(f"HTML report:       {html_path}")

    print_info("Scan complete. Happy hacking (ethically)! 🎯")


if __name__ == "__main__":
    main()
"""
Output & Reporting Utilities
Handles colored terminal output + saving results to files.
"""

import json
import os
import subprocess
from datetime import datetime

# Try colorama, fall back gracefully if not installed
try:
    from colorama import Fore, Style, init
    init(autoreset=True)
    HAS_COLOR = True
except ImportError:
    HAS_COLOR = False
    class Fore:
        RED = YELLOW = GREEN = CYAN = BLUE = MAGENTA = WHITE = ""
    class Style:
        RESET_ALL = BRIGHT = ""


# ─── Colored Print Helpers ─────────────────────────────────────────────────

def print_banner():
    banner = f"""
{Fore.CYAN}
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{Fore.YELLOW}     🔍 Lucuiec-Recon v3.0 — Ultimate Web Hacking Framework
{Fore.RED}     ⚠️  Only scan targets you have permission to test!
{Style.RESET_ALL}"""
    print(banner)


def print_info(msg: str):
    """Blue  [*] info message"""
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def print_found(msg: str):
    """Green [+] found message"""
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def print_error(msg: str):
    """Red   [!] error message"""
    print(f"{Fore.RED}[!]{Style.RESET_ALL} {msg}")


def print_warn(msg: str):
    """Yellow [-] warning message"""
    print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} {msg}")


def print_critical(msg: str):
    """Red bold [!!!] — critical/high-severity finding"""
    print(f"{Fore.RED}{Style.BRIGHT}[!!!]{Style.RESET_ALL} {msg}")


def print_section(title: str):
    """Print a section header"""
    width = 65
    print(f"\n{Fore.CYAN}{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}{Style.RESET_ALL}\n")


def run_cmd(cmd: str, timeout: int = 15) -> str:
    """
    Run a shell command and return its stdout as a string.
    Returns empty string on any error — never crashes the tool.
    Used by modules that need to call external tools (nmap, etc.)
    """
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=timeout
        )
        return (result.stdout or "").strip()
    except subprocess.TimeoutExpired:
        return ""
    except Exception:
        return ""


def print_summary(results: dict):
    """Print a final summary table of all findings"""
    print_section("📊 SCAN SUMMARY")

    target = results.get("target", "unknown")
    print_info(f"Target: {target}")
    print_info(f"Scan Time: {results.get('timestamp', 'N/A')}")
    print()

    # Subdomains
    subs = results.get("subdomains", [])
    print(f"{Fore.CYAN}  Subdomains Found:{Style.RESET_ALL} {len(subs)}")
    for s in subs[:10]:
        print(f"    • {s['subdomain']} → {', '.join(s['ips'])}")
    if len(subs) > 10:
        print(f"    ... and {len(subs) - 10} more (see report file)")

    # Ports
    ports = results.get("ports", {})
    open_ports = ports.get("open_ports", [])
    services = ports.get("services", [])
    print(f"\n{Fore.CYAN}  Open Ports:{Style.RESET_ALL} {open_ports}")
    for svc in services:
        ver = f"{svc.get('product','')} {svc.get('version','')}".strip()
        cve_count = len(svc.get("cves", []))
        cve_str = f" [{Fore.RED}{cve_count} CVEs{Style.RESET_ALL}]" if cve_count else ""
        print(f"    • {svc['port']}/{svc.get('protocol','tcp')} — {svc['service']} {ver}{cve_str}")

    # Technology
    tech = results.get("technology", {})
    if tech:
        stack = []
        for key in ["server", "language", "framework", "cms"]:
            stack.extend(tech.get(key, []))
        wafs = tech.get("waf", [])
        missing_headers = tech.get("security_headers", {}).get("missing", [])
        print(f"\n{Fore.CYAN}  Tech Stack:{Style.RESET_ALL} {', '.join(stack) or 'Unknown'}")
        if wafs:
            print(f"  {Fore.YELLOW}  WAF Detected:{Style.RESET_ALL} {', '.join(wafs)}")
        if missing_headers:
            print(f"  {Fore.YELLOW}  Missing Security Headers:{Style.RESET_ALL} {len(missing_headers)}")

    # CVEs
    all_cves = []
    for svc in services:
        all_cves.extend(svc.get("cves", []))
    if all_cves:
        critical = [c for c in all_cves if c.get("severity") == "CRITICAL"]
        high     = [c for c in all_cves if c.get("severity") == "HIGH"]
        print(f"\n{Fore.RED}  ⚠️  CVEs Found:{Style.RESET_ALL} {len(all_cves)} total "
              f"({len(critical)} CRITICAL, {len(high)} HIGH)")

    # Sensitive files
    sensitive = results.get("sensitive_files", [])
    exposed = [s for s in sensitive if s.get("status") == 200]
    if sensitive:
        print(f"\n{Fore.CYAN}  Sensitive Files:{Style.RESET_ALL} {len(sensitive)} found "
              f"({Fore.RED}{len(exposed)} exposed (200 OK){Style.RESET_ALL})")
        for s in exposed[:5]:
            print(f"    🚨 {s['url']}")

    # JS Mining
    js = results.get("js_mining", {})
    js_secrets = js.get("secrets", [])
    js_endpoints = js.get("endpoints", [])
    if js_secrets or js_endpoints:
        print(f"\n{Fore.CYAN}  JS Mining:{Style.RESET_ALL} "
              f"{len(js_secrets)} secrets, {len(js_endpoints)} endpoints")

    # Parameters
    params = results.get("parameters", [])
    if params:
        print(f"\n{Fore.CYAN}  Hidden Parameters:{Style.RESET_ALL} {len(params)} found")

    # Directories
    dirs = results.get("directories", [])
    print(f"\n{Fore.CYAN}  Directories/Files Found:{Style.RESET_ALL} {len(dirs)}")
    for d in dirs[:10]:
        print(f"    • [{d['status']}] {d['url']} ({d['size']} bytes)")
    if len(dirs) > 10:
        print(f"    ... and {len(dirs) - 10} more (see report file)")


# ─── File Output ───────────────────────────────────────────────────────────

def save_results(results: dict, output_dir: str = "results") -> str:
    """
    Save full results to a JSON file and a human-readable TXT report.
    Returns the path to the saved JSON file.
    """
    os.makedirs(output_dir, exist_ok=True)
    target = results.get("target", "scan").replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_name = f"{output_dir}/{target}_{timestamp}"

    # Save JSON (machine-readable, full data)
    json_path = f"{base_name}.json"
    with open(json_path, "w") as f:
        json.dump(results, f, indent=2)
    print_found(f"JSON report saved: {json_path}")

    # Save TXT (human-readable summary)
    txt_path = f"{base_name}.txt"
    with open(txt_path, "w") as f:
        f.write(f"RECON REPORT — {results.get('target')}\n")
        f.write(f"Generated: {results.get('timestamp')}\n")
        f.write("=" * 60 + "\n\n")

        f.write("SUBDOMAINS\n" + "-" * 40 + "\n")
        for s in results.get("subdomains", []):
            f.write(f"  {s['subdomain']} → {', '.join(s['ips'])}\n")

        f.write("\nOPEN PORTS & SERVICES\n" + "-" * 40 + "\n")
        f.write(f"  Open Ports: {results.get('ports', {}).get('open_ports', [])}\n")
        for svc in results.get("ports", {}).get("services", []):
            ver = f"{svc.get('product','')} {svc.get('version','')}".strip()
            f.write(f"  {svc['port']}/{svc['protocol']} — {svc['service']} {ver}\n")

        f.write("\nDIRECTORIES / FILES\n" + "-" * 40 + "\n")
        for d in results.get("directories", []):
            f.write(f"  [{d['status']}] {d['url']} ({d['size']} bytes)\n")

    print_found(f"TXT report saved:  {txt_path}")
    return json_path
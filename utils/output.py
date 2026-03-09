"""
Output & Reporting Utilities
Handles colored terminal output + saving results to files.
"""

import json
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama (needed for Windows compatibility)
init(autoreset=True)


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
{Fore.YELLOW}          🔍 Recon Tool v1.0 — For Educational Use Only
{Fore.RED}          ⚠️  Only scan targets you have permission to test!
{Style.RESET_ALL}"""
    print(banner)


def print_info(msg: str):
    """Blue info message"""
    print(f"{Fore.BLUE}[*]{Style.RESET_ALL} {msg}")


def print_found(msg: str):
    """Green found message"""
    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} {msg}")


def print_error(msg: str):
    """Red error message"""
    print(f"{Fore.RED}[!]{Style.RESET_ALL} {msg}")


def print_warn(msg: str):
    """Yellow warning message"""
    print(f"{Fore.YELLOW}[-]{Style.RESET_ALL} {msg}")


def print_section(title: str):
    """Print a section header"""
    width = 60
    print(f"\n{Fore.CYAN}{'═' * width}")
    print(f"  {title}")
    print(f"{'═' * width}{Style.RESET_ALL}\n")


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
    for s in subs[:10]:  # Show first 10
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
        print(f"    • {svc['port']}/{svc['protocol']} — {svc['service']} {ver}")

    # Directories
    dirs = results.get("directories", [])
    print(f"\n{Fore.CYAN}  Directories/Files Found:{Style.RESET_ALL} {len(dirs)}")
    for d in dirs[:15]:
        print(f"    • [{d['status']}] {d['url']} ({d['size']} bytes)")
    if len(dirs) > 15:
        print(f"    ... and {len(dirs) - 15} more (see report file)")


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
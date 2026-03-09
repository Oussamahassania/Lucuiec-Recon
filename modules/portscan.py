"""
Port Scanner & Service Version Detection Module
Uses raw sockets for fast scanning + nmap for deep service/version detection.
"""

import socket
import concurrent.futures
import threading
import nmap
from utils.output import print_found, print_info, print_error

_lock = threading.Lock()

# Common ports to scan by default
TOP_PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143,
    443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080,
    8443, 8888, 9090, 9200, 27017
]


def tcp_connect_scan(host: str, port: int, timeout: float = 1.0) -> bool:
    """
    Raw TCP connect scan using Python sockets.
    Returns True if port is open, False otherwise.
    Teaches you how port scanning works at a low level.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))  # 0 = success = open
        sock.close()
        return result == 0
    except Exception:
        return False


def grab_banner(host: str, port: int, timeout: float = 2.0) -> str:
    """
    Banner grabbing: connect to an open port and read what the service says.
    Services like FTP, SSH, SMTP often announce themselves immediately.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        # Send a generic HTTP request for web ports, otherwise just listen
        if port in [80, 8080, 8443, 443, 8888]:
            sock.send(b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n")
        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()
        sock.close()
        return banner[:200]  # Limit banner length
    except Exception:
        return ""


def fast_port_scan(host: str, ports: list[int], threads: int = 100) -> list[int]:
    """
    Fast raw socket scan to find open ports.
    Step 1: Find which ports are open (speed-focused).
    """
    print_info(f"Fast TCP scan on {host} ({len(ports)} ports, {threads} threads)...")
    open_ports = []

    def check_port(port):
        if tcp_connect_scan(host, port):
            with _lock:
                open_ports.append(port)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(check_port, ports)

    return sorted(open_ports)


def nmap_service_scan(host: str, ports: list[int]) -> list[dict]:
    """
    Deep service/version detection using nmap on confirmed open ports.
    Step 2: Get detailed info on open ports found in step 1.

    nmap flags used:
      -sV  → version detection
      -sC  → default scripts (grabs extra info)
      -O   → OS detection (requires root/sudo)
      --open → only show open ports
    """
    if not ports:
        return []

    print_info(f"Running nmap service detection on {len(ports)} open ports...")
    results = []

    try:
        nm = nmap.PortScanner()
        port_str = ",".join(str(p) for p in ports)

        # -sV = version detection, -sC = default scripts, --open = only open
        nm.scan(hosts=host, ports=port_str, arguments="-sV -sC --open -T4")

        if host not in nm.all_hosts():
            print_error("Nmap: host not found in results.")
            return []

        for proto in nm[host].all_protocols():
            port_list = nm[host][proto].keys()
            for port in port_list:
                info = nm[host][proto][port]
                entry = {
                    "port": port,
                    "protocol": proto,
                    "state": info.get("state", ""),
                    "service": info.get("name", "unknown"),
                    "product": info.get("product", ""),
                    "version": info.get("version", ""),
                    "extrainfo": info.get("extrainfo", ""),
                    "scripts": info.get("script", {}),
                }
                results.append(entry)
                svc = f"{entry['service']} {entry['product']} {entry['version']}".strip()
                print_found(f"[PORT] {port}/{proto} → {entry['state']} | {svc}")

    except nmap.PortScannerError as e:
        print_error(f"Nmap error: {e}. Is nmap installed? (sudo apt install nmap)")
    except Exception as e:
        print_error(f"Service scan error: {e}")

    return results


def run(host: str, ports: list[int] = None, threads: int = 100, deep: bool = True) -> dict:
    """
    Main entry point for port scanning.
    1. Fast raw socket scan to find open ports
    2. Optional nmap deep scan for service/version info
    """
    if ports is None:
        ports = TOP_PORTS
        print_info(f"No ports specified. Scanning top {len(TOP_PORTS)} common ports.")

    # Step 1: Fast scan
    open_ports = fast_port_scan(host, ports, threads)

    if not open_ports:
        print_info("No open ports found.")
        return {"open_ports": [], "services": []}

    print_info(f"Found {len(open_ports)} open port(s): {open_ports}")

    # Step 2: Banner grabbing (quick, no nmap needed)
    banners = {}
    for port in open_ports:
        banner = grab_banner(host, port)
        if banner:
            banners[port] = banner
            print_found(f"[BANNER] Port {port}: {banner[:80]}...")

    # Step 3: Deep nmap scan
    services = []
    if deep:
        services = nmap_service_scan(host, open_ports)

    return {
        "open_ports": open_ports,
        "banners": banners,
        "services": services,
    }
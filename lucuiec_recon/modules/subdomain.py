"""
Subdomain Enumeration Module
Techniques: DNS brute-force + Certificate Transparency (crt.sh)
"""

import dns.resolver
import requests
import concurrent.futures
import threading
from lucuiec_recon.utils.output import print_found, print_info, print_error

# Thread-safe results list
_lock = threading.Lock()


def query_crtsh(domain: str) -> list[str]:
    """
    Passive recon via Certificate Transparency logs (crt.sh).
    No wordlist needed — queries public SSL certificate database.
    """
    print_info("Querying crt.sh for certificate transparency logs...")
    found = []
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            for entry in data:
                name = entry.get("name_value", "")
                # crt.sh can return multi-line entries
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    if sub.endswith(f".{domain}") and sub not in found:
                        found.append(sub)
    except Exception as e:
        print_error(f"crt.sh query failed: {e}")
    return found


def resolve_subdomain(subdomain: str) -> dict | None:
    """
    Try to resolve a subdomain via DNS A record lookup.
    Returns dict with subdomain + IP if resolved, else None.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 2
    try:
        answers = resolver.resolve(subdomain, "A")
        ips = [str(r) for r in answers]
        return {"subdomain": subdomain, "ips": ips}
    except Exception:
        return None


def brute_force_subdomains(domain: str, wordlist_path: str, threads: int = 50) -> list[dict]:
    """
    DNS brute-force: try every word in the wordlist as a subdomain.
    Uses threading for speed.
    """
    print_info(f"Starting DNS brute-force with {threads} threads...")
    results = []

    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print_error(f"Wordlist not found: {wordlist_path}")
        return []

    print_info(f"Loaded {len(words)} words from wordlist.")
    candidates = [f"{word}.{domain}" for word in words]

    def worker(subdomain):
        result = resolve_subdomain(subdomain)
        if result:
            with _lock:
                results.append(result)
                print_found(f"[SUBDOMAIN] {subdomain} → {', '.join(result['ips'])}")

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        executor.map(worker, candidates)

    return results


def run(domain: str, wordlist: str, threads: int = 50, passive: bool = True) -> list[dict]:
    """
    Main entry point for subdomain enumeration.
    Combines passive (crt.sh) + active (DNS brute-force).
    """
    all_results = []
    seen = set()

    # --- Passive: crt.sh ---
    if passive:
        crt_subs = query_crtsh(domain)
        print_info(f"crt.sh returned {len(crt_subs)} subdomains. Resolving...")
        for sub in crt_subs:
            if sub not in seen:
                seen.add(sub)
                result = resolve_subdomain(sub)
                if result:
                    all_results.append(result)
                    print_found(f"[SUBDOMAIN][PASSIVE] {sub} → {', '.join(result['ips'])}")

    # --- Active: DNS Brute-force ---
    bf_results = brute_force_subdomains(domain, wordlist, threads)
    for r in bf_results:
        if r["subdomain"] not in seen:
            seen.add(r["subdomain"])
            all_results.append(r)

    return all_results
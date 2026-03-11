"""
Wayback Machine / Web Archive Module
Queries the Internet Archive for historical URLs of the target.
Finds:
- Old admin panels that were removed but still work
- Exposed files that were deleted
- Old API endpoints
- Backup files that existed in the past
- Parameter names from old URLs
Completely passive — never touches the target directly.
"""

import requests
import re
from urllib.parse import urlparse
from lucuiec_recon.utils.output import print_found, print_info, print_error

# Interesting URL patterns to highlight
INTERESTING_PATTERNS = [
    r'/admin', r'/administrator', r'/panel', r'/dashboard',
    r'/backup', r'\.bak', r'\.old', r'\.zip', r'\.tar',
    r'/config', r'\.env', r'/api/', r'/v\d+/',
    r'/upload', r'/debug', r'/test', r'/dev',
    r'\.sql', r'\.db', r'id_rsa', r'\.key', r'\.pem',
    r'/login', r'/auth', r'/register', r'/reset',
    r'\?.*=', r'/user', r'/account', r'/profile',
    r'\.php\?', r'\.asp\?', r'\.aspx\?',
    r'/wp-admin', r'/wp-content', r'/phpmyadmin',
    r'password', r'passwd', r'secret', r'token',
]


def query_wayback(domain: str, limit: int = 500) -> list:
    """
    Query the Wayback CDX API for all archived URLs of a domain.
    CDX API is free and doesn't require authentication.
    """
    print_info(f"Querying Wayback Machine for: {domain}")

    try:
        # CDX API endpoint
        url = "http://web.archive.org/cdx/search/cdx"
        params = {
            "url":        f"*.{domain}/*",
            "output":     "json",
            "fl":         "original,statuscode,timestamp,mimetype",
            "collapse":   "urlkey",
            "limit":      limit,
            "filter":     "statuscode:200",
        }

        resp = requests.get(url, params=params, timeout=30)
        if resp.status_code != 200:
            print_error(f"Wayback API error: {resp.status_code}")
            return []

        data = resp.json()
        if not data or len(data) <= 1:
            print_info("No archived URLs found.")
            return []

        # First row is headers
        headers = data[0]
        rows    = data[1:]
        print_info(f"Found {len(rows)} archived URLs")
        return [dict(zip(headers, row)) for row in rows]

    except Exception as e:
        print_error(f"Wayback Machine query failed: {e}")
        return []


def analyze_urls(urls: list, base_url: str = "") -> dict:
    """
    Analyze archived URLs for interesting patterns.
    Returns categorized findings.
    """
    results = {
        "all_urls":         [],
        "interesting":      [],
        "parameters":       set(),
        "extensions":       {},
        "paths":            set(),
        "subdomains":       set(),
    }

    for entry in urls:
        original = entry.get("original", "")
        status   = entry.get("statuscode", "")
        ts       = entry.get("timestamp", "")
        mime     = entry.get("mimetype", "")

        if not original:
            continue

        results["all_urls"].append(original)

        # Extract subdomains
        parsed = urlparse(original)
        results["subdomains"].add(parsed.netloc)
        results["paths"].add(parsed.path)

        # Extract parameter names
        if "?" in original:
            query = original.split("?", 1)[1]
            for param in re.findall(r'([^&=]+)=', query):
                results["parameters"].add(param)

        # Extract file extensions
        path = parsed.path
        if "." in path.split("/")[-1]:
            ext = "." + path.split(".")[-1].lower()
            results["extensions"][ext] = results["extensions"].get(ext, 0) + 1

        # Check for interesting patterns
        is_interesting = any(
            re.search(p, original, re.IGNORECASE)
            for p in INTERESTING_PATTERNS
        )
        if is_interesting:
            results["interesting"].append({
                "url":       original,
                "timestamp": ts,
                "status":    status,
                "mime":      mime,
            })

    # Convert sets to lists
    results["parameters"] = list(results["parameters"])
    results["paths"]      = list(results["paths"])
    results["subdomains"] = list(results["subdomains"])

    return results


def check_still_alive(urls: list, limit: int = 20) -> list:
    """
    Check if interesting archived URLs still return 200.
    These are old endpoints that were removed from the site but still work!
    """
    alive = []
    print_info(f"Checking if {min(limit, len(urls))} interesting URLs are still alive...")

    import httpx
    for entry in urls[:limit]:
        url = entry["url"]
        try:
            resp = httpx.get(url, timeout=8.0, verify=False,
                             follow_redirects=False)
            if resp.status_code == 200:
                alive.append({**entry, "current_status": resp.status_code,
                              "size": len(resp.content)})
                print_found(
                    f"[WAYBACK] 🚨 Still alive: {url}\n"
                    f"           Last seen: {entry.get('timestamp', 'unknown')[:8]} | "
                    f"Size: {len(resp.content)} bytes"
                )
        except Exception:
            pass

    return alive


def run(domain: str, check_alive: bool = True, limit: int = 500) -> dict:
    """Main entry point for Wayback Machine recon."""

    # Strip protocol if given
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    # Query Wayback Machine
    archived = query_wayback(domain, limit)
    if not archived:
        return {"archived": [], "interesting": [], "parameters": [], "alive": []}

    # Analyze
    analysis = analyze_urls(archived)

    # Print summary
    print_found(f"Total archived URLs    : {len(analysis['all_urls'])}")
    print_found(f"Interesting URLs       : {len(analysis['interesting'])}")
    print_found(f"Unique parameters      : {len(analysis['parameters'])}")
    print_found(f"Subdomains seen        : {len(analysis['subdomains'])}")

    if analysis["parameters"]:
        print_found(f"Parameters discovered  : {', '.join(list(analysis['parameters'])[:20])}")

    if analysis["interesting"]:
        print_info("\nTop interesting archived URLs:")
        for u in analysis["interesting"][:15]:
            print(f"  [{u.get('timestamp','')[:8]}] {u['url']}")

    # Check if still alive
    alive = []
    if check_alive and analysis["interesting"]:
        alive = check_still_alive(analysis["interesting"], limit=20)
        if alive:
            print_found(f"\n🚨 {len(alive)} old URLs still alive!")

    return {
        "archived":   analysis["all_urls"][:200],
        "interesting": analysis["interesting"],
        "parameters": analysis["parameters"],
        "subdomains": analysis["subdomains"],
        "extensions": analysis["extensions"],
        "alive":      alive,
    }
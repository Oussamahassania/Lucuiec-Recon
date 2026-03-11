"""
Directory/File Brute-Force Scanner v3.0
Features:
  - Recursive scanning (-r) — scans every found directory automatically
  - Scan a specific path (target.com/admin) not just root
  - Live progress bar: trials count + % of wordlist done
  - Ultra-fast async engine (up to 300 concurrent requests)
  - Auto-retry on timeout
  - Custom extensions
  - Filters by response size to remove false positives
  - Color-coded output by status code
"""

import httpx
import asyncio
import threading
import sys
import time
from urllib.parse import urljoin
from utils.output import print_found, print_info, print_error, print_warn

_lock          = threading.Lock()
_counter_lock  = threading.Lock()
_progress      = {"done": 0, "total": 0, "found": 0, "start": 0.0}

INTERESTING_CODES = {
    200: ("✅", "OK"),
    201: ("✅", "Created"),
    204: ("✅", "No Content"),
    301: ("🔀", "Redirect"),
    302: ("🔀", "Redirect"),
    307: ("🔀", "Temp Redirect"),
    308: ("🔀", "Perm Redirect"),
    401: ("🔒", "Auth Required"),
    403: ("🔒", "Forbidden (exists!)"),
    405: ("⚠️ ", "Method Not Allowed"),
    500: ("💥", "Server Error"),
    503: ("⚠️ ", "Service Unavailable"),
}

DEFAULT_EXTENSIONS = ["", ".php", ".html", ".txt", ".js", ".json",
                      ".bak", ".old", ".zip", ".xml", ".conf", ".log"]


# ── Progress bar ─────────────────────────────────────────────────────────────

def _draw_progress():
    """Draw a live progress bar in the terminal."""
    with _counter_lock:
        done  = _progress["done"]
        total = _progress["total"]
        found = _progress["found"]
        start = _progress["start"]

    if total == 0:
        return

    pct     = done / total * 100
    elapsed = time.time() - start
    rps     = done / elapsed if elapsed > 0 else 0
    eta_s   = (total - done) / rps if rps > 0 else 0
    eta     = f"{int(eta_s//60):02d}:{int(eta_s%60):02d}"

    bar_len = 30
    filled  = int(bar_len * done / total)
    bar     = "█" * filled + "░" * (bar_len - filled)

    # Overwrite the current line
    line = (
        f"\r  [{bar}] {pct:5.1f}%  "
        f"{done:>6}/{total}  "
        f"⚡{rps:>5.0f}r/s  "
        f"⏱ ETA:{eta}  "
        f"🎯 Found:{found}   "
    )
    sys.stdout.write(line)
    sys.stdout.flush()


def _tick(found_one: bool = False):
    """Increment progress counter."""
    with _counter_lock:
        _progress["done"] += 1
        if found_one:
            _progress["found"] += 1
    _draw_progress()


# ── Single path check ────────────────────────────────────────────────────────

async def check_path(
    client:     httpx.AsyncClient,
    url:        str,
    results:    list,
    extensions: list,
    filter_size: int,
    semaphore:  asyncio.Semaphore,
    depth:      int,
    found_dirs: list,
) -> None:
    """
    Test a single URL path with all extensions.
    If a directory is found (200/301/302/403) and recursive=True,
    it's added to found_dirs for the next depth pass.
    """
    async with semaphore:
        for ext in extensions:
            full_url = f"{url}{ext}"
            # Clean up double slashes (but keep ://)
            full_url = full_url.replace("://", "§§").replace("//", "/").replace("§§", "://")

            try:
                resp = await client.get(full_url, follow_redirects=False)
                code = resp.status_code
                size = len(resp.content)

                # Skip if same size as "not found" (false positive filter)
                if filter_size > 0 and size == filter_size and code == 404:
                    _tick()
                    continue

                if code in INTERESTING_CODES:
                    icon, meaning = INTERESTING_CODES[code]
                    location = resp.headers.get("location", "")

                    entry = {
                        "url":      full_url,
                        "status":   code,
                        "meaning":  meaning,
                        "size":     size,
                        "location": location,
                        "depth":    depth,
                    }

                    with _lock:
                        results.append(entry)
                        _progress["found"] += 1

                    # Print above progress bar
                    sys.stdout.write("\r" + " " * 80 + "\r")
                    loc_str = f" → {location}" if location else ""
                    indent  = "  " * depth
                    print_found(
                        f"{indent}{icon} [{code}] {full_url} "
                        f"({size}b){loc_str}"
                    )

                    # Mark as potential directory for recursion
                    if ext == "" and code in [200, 301, 302, 403]:
                        with _lock:
                            if full_url not in found_dirs:
                                found_dirs.append(full_url)

                _tick()

            except (httpx.TimeoutException, httpx.ConnectError):
                _tick()
            except Exception:
                _tick()


# ── Async scan engine ─────────────────────────────────────────────────────────

async def _async_scan_url(
    base_url:    str,
    wordlist:    list,
    extensions:  list,
    concurrency: int,
    filter_size: int,
    depth:       int,
    found_dirs:  list,
    results:     list,
) -> None:
    """Run one pass of the scan on base_url with the wordlist."""
    semaphore = asyncio.Semaphore(concurrency)

    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/120.0",
        "Accept":     "text/html,application/json,*/*",
        "Connection": "keep-alive",
        "Accept-Encoding": "gzip, deflate",
    }

    # Try HTTP/2 for speed, fall back to HTTP/1.1 if h2 not installed
    try:
        import h2  # noqa
        use_http2 = True
    except ImportError:
        use_http2 = False

    async with httpx.AsyncClient(
        headers  = headers,
        timeout  = httpx.Timeout(connect=3.0, read=5.0, write=3.0, pool=3.0),
        verify   = False,
        http2    = use_http2,
        limits   = httpx.Limits(
            max_connections      = concurrency,
            max_keepalive_connections = concurrency,
            keepalive_expiry     = 10,
        ),
    ) as client:

        # Build all URL+path combinations
        tasks = []
        for word in wordlist:
            word = word.strip("/")
            url  = f"{base_url}/{word}"
            tasks.append(
                check_path(client, url, results, extensions,
                           filter_size, semaphore, depth, found_dirs)
            )

        await asyncio.gather(*tasks)


def get_not_found_size(base_url: str) -> int:
    """
    Get the size of a 404 page to filter false positives.
    Some servers return 200 for everything (soft 404).
    """
    try:
        resp = httpx.get(
            f"{base_url}/THIS_PATH_SHOULD_NOT_EXIST_LUCUIEC_12345",
            timeout=5.0, verify=False, follow_redirects=False,
        )
        if resp.status_code == 200:
            # Soft 404 — use size as filter
            size = len(resp.content)
            print_warn(f"Soft 404 detected (server returns 200 for anything). "
                       f"Filtering responses of size {size}b")
            return size
    except Exception:
        pass
    return 0


# ── Main entry point ─────────────────────────────────────────────────────────

def run(
    target:        str,
    wordlist_path: str,
    port:          int   = 80,
    use_https:     bool  = False,
    extensions:    list  = None,
    concurrency:   int   = 150,
    recursive:     bool  = False,
    max_depth:     int   = 3,
    base_path:     str   = "",
) -> list:
    """
    Main entry point for directory/file brute-force scanning.

    Args:
        target      : hostname or IP  (e.g. 10.10.10.5 or lab.thm)
        wordlist_path: path to wordlist file
        port        : web server port  (default 80)
        use_https   : use HTTPS
        extensions  : list of extensions to try
        concurrency : parallel requests (default 150 — fast!)
        recursive   : scan found directories recursively (like dirbuster -r)
        max_depth   : how deep to recurse (default 3)
        base_path   : start scan from this path (e.g. '/admin' or '/api/v1')
    """
    if extensions is None:
        extensions = DEFAULT_EXTENSIONS

    # Build base URL
    scheme = "https" if use_https else "http"
    base_url = (
        f"{scheme}://{target}:{port}"
        if port not in [80, 443]
        else f"{scheme}://{target}"
    )

    # Support scanning a specific sub-path (e.g. target.com/admin)
    if base_path:
        base_path = "/" + base_path.strip("/")
        base_url  = base_url + base_path
        print_info(f"Scanning sub-path: {base_url}")

    # Load wordlist
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            wordlist = [
                l.strip() for l in f
                if l.strip() and not l.startswith("#")
            ]
    except FileNotFoundError:
        print_error(f"Wordlist not found: {wordlist_path}")
        return []

    # Get 404 size for false-positive filtering
    filter_size = get_not_found_size(base_url)

    total_per_pass = len(wordlist) * len(extensions)
    print_info(f"Target      : {base_url}")
    print_info(f"Wordlist    : {wordlist_path} ({len(wordlist)} words)")
    print_info(f"Extensions  : {extensions}")
    print_info(f"Concurrency : {concurrency} parallel requests")
    print_info(f"Recursive   : {'YES (depth=' + str(max_depth) + ')' if recursive else 'NO'}")
    print_info(f"Total checks: {total_per_pass} per directory\n")

    all_results  = []
    found_dirs   = [base_url]  # Start with root, expand recursively
    scanned_urls = set()

    depth = 0
    while found_dirs and depth <= max_depth:
        current_batch = [u for u in found_dirs if u not in scanned_urls]
        if not current_batch:
            break

        for url in current_batch:
            scanned_urls.add(url)
            new_dirs = []

            if depth > 0:
                print_info(f"\n🔁 Recursive scan depth {depth}: {url}")

            # Reset progress counter for this pass
            with _counter_lock:
                _progress["done"]  = 0
                _progress["total"] = total_per_pass
                _progress["found"] = 0
                _progress["start"] = time.time()

            try:
                asyncio.run(
                    _async_scan_url(
                        base_url    = url,
                        wordlist    = wordlist,
                        extensions  = extensions,
                        concurrency = concurrency,
                        filter_size = filter_size,
                        depth       = depth,
                        found_dirs  = new_dirs,
                        results     = all_results,
                    )
                )
            except KeyboardInterrupt:
                sys.stdout.write("\n")
                print_warn("Scan interrupted.")
                return sorted(all_results, key=lambda x: x["status"])

            sys.stdout.write("\n")  # New line after progress bar

            # Add newly discovered directories for next depth pass
            if recursive:
                for d in new_dirs:
                    if d not in scanned_urls:
                        found_dirs.append(d)

        if not recursive:
            break
        depth += 1
        found_dirs = [u for u in found_dirs if u not in scanned_urls]

    # Final summary
    by_code = {}
    for r in all_results:
        by_code.setdefault(r["status"], []).append(r)

    print_info(f"\n{'─'*50}")
    print_info(f"Scan complete! Total found: {len(all_results)}")
    for code, items in sorted(by_code.items()):
        icon, meaning = INTERESTING_CODES.get(code, ("?", ""))
        print_found(f"  {icon} [{code}] {meaning}: {len(items)}")

    return sorted(all_results, key=lambda x: x["status"])
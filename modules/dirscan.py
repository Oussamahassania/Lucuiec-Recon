"""
Web Directory & File Discovery Module
Brute-forces hidden paths on web servers using wordlists.
Async HTTP with httpx for maximum speed.
"""

import httpx
import asyncio
import threading
from utils.output import print_found, print_info, print_error, print_warn

_lock = threading.Lock()

# HTTP status codes that mean "something is there"
INTERESTING_CODES = {
    200: "OK",
    201: "Created",
    204: "No Content",
    301: "Moved Permanently",
    302: "Found (Redirect)",
    307: "Temporary Redirect",
    401: "Unauthorized (Auth Required)",
    403: "Forbidden (Exists but Blocked)",
    405: "Method Not Allowed",
    500: "Server Error (Interesting!)",
}

# Extensions to try appending to each word
EXTENSIONS = ["", ".php", ".html", ".txt", ".js", ".json", ".bak", ".old", ".zip"]


async def check_path(
        client: httpx.AsyncClient,
        base_url: str,
        path: str,
        results: list,
        extensions: list[str],
):
    """
    Send async HTTP GET request and check the response status.
    Tries the path with multiple file extensions.
    """
    for ext in extensions:
        url = f"{base_url}/{path}{ext}".replace("//", "/")
        # Fix double slash at protocol boundary
        url = url.replace(":/", "://")
        try:
            resp = await client.get(url, follow_redirects=False)
            code = resp.status_code

            if code in INTERESTING_CODES:
                size = len(resp.content)
                entry = {
                    "url": url,
                    "status": code,
                    "meaning": INTERESTING_CODES[code],
                    "size": size,
                }
                with _lock:
                    results.append(entry)
                    color_code = "✅" if code == 200 else "⚠️" if code in [401, 403] else "🔀"
                    print_found(
                        f"{color_code} [{code}] {url} ({size} bytes)"
                    )
        except httpx.TimeoutException:
            pass  # Silently skip timeouts
        except Exception:
            pass  # Silently skip connection errors


async def _async_dir_scan(
        base_url: str,
        wordlist: list[str],
        extensions: list[str],
        concurrency: int,
) -> list[dict]:
    """
    Async engine: fires many HTTP requests concurrently using semaphore.
    A semaphore limits how many requests run at the same time.
    """
    results = []
    semaphore = asyncio.Semaphore(concurrency)  # Max concurrent requests

    # Configure client with realistic browser headers
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ReconTool/1.0",
        "Accept": "*/*",
        "Connection": "keep-alive",
    }

    async with httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(5.0),
            verify=False,  # Skip SSL verification for CTF/lab targets
            limits=httpx.Limits(max_connections=concurrency),
    ) as client:
        async def bounded_check(path):
            async with semaphore:
                await check_path(client, base_url, path, results, extensions)

        tasks = [bounded_check(word) for word in wordlist]
        await asyncio.gather(*tasks)

    return results


def run(
        target: str,
        wordlist_path: str,
        port: int = 80,
        use_https: bool = False,
        extensions: list[str] = None,
        concurrency: int = 50,
) -> list[dict]:
    """
    Main entry point for directory/file discovery.

    Args:
        target: hostname or IP (e.g. 10.10.10.5)
        wordlist_path: path to wordlist file
        port: web server port (default 80)
        use_https: use HTTPS instead of HTTP
        extensions: file extensions to try (default: common web extensions)
        concurrency: number of parallel requests
    """
    if extensions is None:
        extensions = EXTENSIONS

    # Build base URL
    scheme = "https" if use_https else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        base_url = f"{scheme}://{target}"
    else:
        base_url = f"{scheme}://{target}:{port}"

    print_info(f"Target URL: {base_url}")
    print_info(f"Extensions: {extensions}")
    print_info(f"Concurrency: {concurrency} parallel requests")

    # Load wordlist
    try:
        with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    except FileNotFoundError:
        print_error(f"Wordlist not found: {wordlist_path}")
        return []

    print_info(f"Loaded {len(words)} words. Starting scan...")
    print_warn("Note: SSL verification disabled for lab/CTF targets.")

    # Run async scan
    try:
        results = asyncio.run(
            _async_dir_scan(base_url, words, extensions, concurrency)
        )
    except KeyboardInterrupt:
        print_warn("Scan interrupted by user.")
        results = []

    # Sort by status code
    results.sort(key=lambda x: x["status"])
    return results
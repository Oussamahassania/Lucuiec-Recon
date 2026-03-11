"""
Virtual Host (VHost) Fuzzing Module
Discovers hidden virtual hosts on the same IP.
Technique: send requests with different Host headers and compare responses.
A different response = a different vhost exists!
Examples: admin.target.com, dev.target.com, internal.target.com
"""

import httpx
import asyncio
import threading
from lucuiec_recon.utils.output import print_found, print_info, print_warn

_lock = threading.Lock()

# Common vhost prefixes to try
DEFAULT_VHOST_WORDLIST = [
    "www", "mail", "admin", "administrator", "dev", "development",
    "staging", "stage", "test", "testing", "uat", "qa", "demo",
    "api", "api2", "v1", "v2", "portal", "dashboard", "panel",
    "internal", "intranet", "extranet", "vpn", "remote", "secure",
    "beta", "alpha", "preview", "old", "new", "backup",
    "shop", "store", "blog", "forum", "help", "support", "docs",
    "cdn", "static", "assets", "media", "images", "files",
    "git", "gitlab", "github", "jenkins", "jira", "confluence",
    "wiki", "kb", "monitor", "status", "metrics", "grafana",
    "kibana", "elastic", "db", "database", "mysql", "redis",
    "ftp", "smtp", "mail2", "webmail", "owa", "exchange",
    "app", "apps", "web", "webserver", "server", "host",
    "mobile", "m", "wap", "cloud", "aws", "azure",
    "login", "auth", "sso", "oauth", "idp",
    "proxy", "gateway", "router", "fw", "firewall",
    "cpanel", "whm", "plesk", "webmin",
    "phpmyadmin", "pma", "adminer",
    "prod", "production", "live",
]


async def get_baseline(client: httpx.AsyncClient, host: str, port: int, use_https: bool) -> tuple:
    """Get baseline response for the target IP directly."""
    scheme = "https" if use_https else "http"
    url = f"{scheme}://{host}:{port}" if port not in [80, 443] else f"{scheme}://{host}"
    try:
        resp = await client.get(url, headers={"Host": host})
        return resp.status_code, len(resp.content), resp.text[:500]
    except Exception:
        return 0, 0, ""


async def test_vhost(
    client: httpx.AsyncClient,
    ip: str,
    port: int,
    use_https: bool,
    vhost: str,
    domain: str,
    baseline_size: int,
    results: list,
    semaphore: asyncio.Semaphore,
):
    """Test a single virtual host by changing the Host header."""
    async with semaphore:
        scheme = "https" if use_https else "http"
        url = f"{scheme}://{ip}:{port}" if port not in [80, 443] else f"{scheme}://{ip}"
        host_header = f"{vhost}.{domain}"

        try:
            resp = await client.get(
                url,
                headers={"Host": host_header},
                follow_redirects=False,
            )
            code = resp.status_code
            size = len(resp.content)

            # Different size or specific status = vhost exists
            size_diff = abs(size - baseline_size)
            is_different = (
                size_diff > 100 or          # Meaningfully different content
                code in [200, 201, 301, 302, 401, 403] and size_diff > 50
            )

            if is_different and code != 404:
                entry = {
                    "vhost": host_header,
                    "status": code,
                    "size": size,
                    "size_diff": size_diff,
                }
                with _lock:
                    results.append(entry)
                    icon = "🚨" if code == 200 else "⚠️ "
                    print_found(
                        f"{icon} [VHOST] {host_header} → [{code}] "
                        f"size:{size} (diff:{size_diff})"
                    )
        except Exception:
            pass


async def _async_vhost_scan(
    ip: str, domain: str, port: int, use_https: bool,
    wordlist: list, concurrency: int
) -> list:
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    headers = {"User-Agent": "Mozilla/5.0 ReconTool/3.0"}
    async with httpx.AsyncClient(
        headers=headers, timeout=httpx.Timeout(8.0),
        verify=False,
        limits=httpx.Limits(max_connections=concurrency),
    ) as client:
        # Get baseline
        base_code, base_size, _ = await get_baseline(client, ip, port, use_https)
        print_info(f"Baseline response: [{base_code}] size:{base_size}")

        tasks = [
            test_vhost(client, ip, port, use_https, word, domain,
                       base_size, results, semaphore)
            for word in wordlist
        ]
        await asyncio.gather(*tasks)

    return results


def run(target: str, domain: str = "", port: int = 80,
        use_https: bool = False, wordlist: list = None,
        concurrency: int = 50, wordlist_file: str = "") -> list:
    """
    Main entry point for VHost fuzzing.
    target = IP address of the server
    domain = base domain (e.g. target.com)
    """
    if not domain:
        # If target is already a domain, use it
        if not target.replace(".", "").isdigit():
            domain = target
        else:
            print_warn("No domain specified for VHost fuzzing. Use --vhost-domain example.com")
            return []

    # Load wordlist
    words = DEFAULT_VHOST_WORDLIST.copy()
    if wordlist_file:
        try:
            with open(wordlist_file, "r", errors="ignore") as f:
                words = [l.strip() for l in f if l.strip()]
        except FileNotFoundError:
            print_warn(f"Wordlist not found: {wordlist_file}, using built-in list")
    if wordlist:
        words = wordlist

    print_info(f"VHost fuzzing: {target} with domain={domain}")
    print_info(f"Testing {len(words)} virtual host prefixes...")

    try:
        results = asyncio.run(
            _async_vhost_scan(target, domain, port, use_https, words, concurrency)
        )
    except KeyboardInterrupt:
        print_warn("VHost scan interrupted.")
        return []

    print_info(f"VHosts discovered: {len(results)}")
    return results
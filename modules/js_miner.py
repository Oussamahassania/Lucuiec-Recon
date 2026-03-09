"""
JavaScript File Mining Module
Crawls target web pages, finds all .js files, then extracts:
- Hidden API endpoints
- Hardcoded secrets / tokens / passwords
- Internal IP addresses / hostnames
- Email addresses
- AWS/cloud keys
This finds bugs that dirb/gobuster completely miss.
"""

import re
import httpx
import asyncio
from urllib.parse import urljoin, urlparse
from utils.output import print_found, print_info, print_error, print_warn

# ─── Regex Patterns for Secret Detection ─────────────────────────────────────

PATTERNS = {
    "API Key (Generic)":      r'(?i)(api[_\-]?key|apikey)\s*[=:]\s*["\']([a-zA-Z0-9\-_]{16,})["\']',
    "Secret/Password":        r'(?i)(secret|password|passwd|pwd)\s*[=:]\s*["\']([^\'"]{6,})["\']',
    "AWS Access Key":         r'AKIA[0-9A-Z]{16}',
    "AWS Secret Key":         r'(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[=:]\s*["\']([^\'"]{20,})["\']',
    "Bearer Token":           r'(?i)bearer\s+([a-zA-Z0-9\-_\.]{20,})',
    "JWT Token":              r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
    "Private Key":            r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----',
    "GitHub Token":           r'ghp_[a-zA-Z0-9]{36}',
    "Google API Key":         r'AIza[0-9A-Za-z\-_]{35}',
    "Slack Token":            r'xox[baprs]-[0-9a-zA-Z\-]{10,}',
    "Stripe Key":             r'(?:sk|pk)_(test|live)_[0-9a-zA-Z]{24,}',
    "Email Address":          r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "Internal IP":            r'(?:10\.|172\.(?:1[6-9]|2\d|3[01])\.|192\.168\.)\d{1,3}\.\d{1,3}',
    "API Endpoint":           r'(?:"|\'|`)(/(?:api|v\d|rest|graphql|admin|internal)[^\s"\'`]*)',
    "S3 Bucket":              r's3\.amazonaws\.com/([a-zA-Z0-9\-_\.]+)',
    "Firebase URL":           r'https://[a-zA-Z0-9\-]+\.firebaseio\.com',
    "Database Connection":    r'(?i)(mongodb|mysql|postgres|redis|jdbc)://[^\s"\'<>]+',
    "Basic Auth in URL":      r'https?://[a-zA-Z0-9]+:[^@\s]+@[^\s]+',
}


async def fetch_page(client: httpx.AsyncClient, url: str) -> str:
    """Fetch a URL and return its text content."""
    try:
        resp = await client.get(url, follow_redirects=True)
        if resp.status_code == 200:
            return resp.text
    except Exception:
        pass
    return ""


def extract_js_urls(html: str, base_url: str) -> list[str]:
    """
    Extract all JavaScript file URLs from an HTML page.
    Finds <script src="..."> tags.
    """
    pattern = r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']'
    matches = re.findall(pattern, html, re.IGNORECASE)
    js_urls = []
    for match in matches:
        full_url = urljoin(base_url, match)
        # Only include JS from same domain or relative paths
        if urlparse(full_url).netloc == urlparse(base_url).netloc or match.startswith("/"):
            js_urls.append(full_url)
    return list(set(js_urls))


def extract_secrets(js_content: str, js_url: str) -> list[dict]:
    """
    Run all regex patterns against JS content to find secrets.
    Returns list of findings with type, value, and source file.
    """
    findings = []
    lines = js_content.split("\n")

    for pattern_name, pattern in PATTERNS.items():
        matches = re.finditer(pattern, js_content)
        for match in matches:
            value = match.group(0)
            # Find which line it's on
            char_pos = match.start()
            line_num = js_content[:char_pos].count("\n") + 1

            # Skip obvious false positives
            if pattern_name == "Internal IP" and value.startswith("192.168.0."):
                continue
            if len(value) < 4:
                continue

            findings.append({
                "type": pattern_name,
                "value": value[:150],  # Truncate very long values
                "line": line_num,
                "source": js_url,
            })

    return findings


def extract_endpoints(js_content: str) -> list[str]:
    """
    Extract API endpoint paths from JS content.
    Finds patterns like '/api/v1/users', '/admin/panel', etc.
    """
    patterns = [
        r'["\'`](/(?:api|v\d+|rest|graphql|admin|internal|auth|user|account)[^"\'`\s]*)',
        r'fetch\(["\']([^"\']+)["\']',
        r'axios\.[a-z]+\(["\']([^"\']+)["\']',
        r'\.get\(["\']([/][^"\']+)["\']',
        r'\.post\(["\']([/][^"\']+)["\']',
        r'url:\s*["\']([/][^"\']+)["\']',
    ]
    endpoints = set()
    for pattern in patterns:
        matches = re.findall(pattern, js_content, re.IGNORECASE)
        for m in matches:
            if len(m) > 2 and not m.endswith(".js"):
                endpoints.add(m)
    return list(endpoints)


async def _async_mine(base_url: str, concurrency: int) -> dict:
    """Async engine: fetch homepage, find JS files, mine each one."""
    all_secrets = []
    all_endpoints = set()
    js_files_found = []

    headers = {"User-Agent": "Mozilla/5.0 ReconTool/2.0"}

    async with httpx.AsyncClient(
        headers=headers,
        timeout=httpx.Timeout(10.0),
        verify=False,
        limits=httpx.Limits(max_connections=concurrency),
    ) as client:

        # Step 1: Fetch homepage
        print_info(f"Fetching homepage: {base_url}")
        html = await fetch_page(client, base_url)
        if not html:
            print_error("Could not fetch homepage.")
            return {"js_files": [], "secrets": [], "endpoints": []}

        # Step 2: Extract JS file URLs
        js_urls = extract_js_urls(html, base_url)
        print_info(f"Found {len(js_urls)} JavaScript files.")
        js_files_found = js_urls

        # Also mine the HTML itself for secrets/endpoints
        html_secrets = extract_secrets(html, base_url + " [HTML]")
        html_endpoints = extract_endpoints(html)
        all_secrets.extend(html_secrets)
        all_endpoints.update(html_endpoints)

        # Step 3: Fetch and mine each JS file
        semaphore = asyncio.Semaphore(concurrency)

        async def mine_js(url):
            async with semaphore:
                content = await fetch_page(client, url)
                if content:
                    secrets = extract_secrets(content, url)
                    endpoints = extract_endpoints(content)
                    return secrets, endpoints
                return [], []

        tasks = [mine_js(url) for url in js_urls]
        results = await asyncio.gather(*tasks)

        for secrets, endpoints in results:
            all_secrets.extend(secrets)
            all_endpoints.update(endpoints)

    # Deduplicate secrets
    seen = set()
    unique_secrets = []
    for s in all_secrets:
        key = (s["type"], s["value"])
        if key not in seen:
            seen.add(key)
            unique_secrets.append(s)

    return {
        "js_files": js_files_found,
        "secrets": unique_secrets,
        "endpoints": sorted(list(all_endpoints)),
    }


def run(target: str, port: int = 80, use_https: bool = False, concurrency: int = 20) -> dict:
    """
    Main entry point for JS mining.
    """
    scheme = "https" if use_https else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        base_url = f"{scheme}://{target}"
    else:
        base_url = f"{scheme}://{target}:{port}"

    print_info(f"Starting JS mining on: {base_url}")

    try:
        results = asyncio.run(_async_mine(base_url, concurrency))
    except KeyboardInterrupt:
        print_warn("JS mining interrupted.")
        return {"js_files": [], "secrets": [], "endpoints": []}

    # Print summary
    secrets = results["secrets"]
    endpoints = results["endpoints"]
    js_files = results["js_files"]

    print_info(f"JS files analyzed: {len(js_files)}")

    if endpoints:
        print_found(f"[JS] Found {len(endpoints)} API endpoints:")
        for ep in endpoints[:20]:
            print(f"      → {ep}")

    if secrets:
        print_found(f"[JS] Found {len(secrets)} potential secrets/sensitive data:")
        for s in secrets:
            icon = "🚨" if s["type"] in ["AWS Access Key", "Private Key", "JWT Token", "GitHub Token"] else "⚠️"
            print_found(f"{icon} [{s['type']}] Line {s['line']} in {s['source'].split('/')[-1]}")
            print(f"      ↳ {s['value'][:100]}")
    else:
        print_info("No secrets found in JS files.")

    return results
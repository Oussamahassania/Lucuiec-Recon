"""
Web Crawler & URL Finder Module
Crawls the target website and extracts:
- All internal URLs and links
- Forms and their input fields
- Comments in HTML (devs leave passwords/notes in comments)
- Email addresses
- Phone numbers
- External links (third-party services used)
- API endpoints from page content
- Hidden input fields
Uses async httpx for speed with depth control.
"""

import httpx
import asyncio
import re
from urllib.parse import urljoin, urlparse
from lucuiec_recon.utils.output import print_found, print_info, print_warn

# Regex patterns for URL/data extraction
PATTERNS = {
    "emails":       r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}',
    "phones":       r'[\+]?[(]?[0-9]{3}[)]?[-\s\.]?[0-9]{3}[-\s\.]?[0-9]{4,6}',
    "api_paths":    r'["\'`](/(?:api|v\d+|rest|graphql|admin|internal|auth)[^"\'`\s<>]{0,100})',
    "html_comments":r'<!--(.*?)-->',
    "js_urls":      r'["\'`]((?:https?://|/)[^"\'`\s]{5,200})["\']',
    "aws_s3":       r's3\.amazonaws\.com/([a-zA-Z0-9\-_\.]+)',
    "ip_addresses": r'\b(?:10|172(?:\.1[6-9]|\.2\d|\.3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b',
    "jwt_tokens":   r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+',
    "version_info": r'(?:version|ver|v)[:\s]+(\d+\.\d+[\.\d]*)',
}

# File extensions to skip (binary files)
SKIP_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".ico",
    ".pdf", ".zip", ".tar", ".gz", ".rar", ".exe", ".bin",
    ".mp4", ".mp3", ".avi", ".mov", ".woff", ".woff2", ".ttf",
    ".eot", ".otf", ".map",
}


def extract_links(html: str, base_url: str, domain: str) -> tuple[list, list]:
    """Extract all links from HTML, split into internal and external."""
    internal = []
    external = []

    # href and src attributes
    all_links = re.findall(
        r'(?:href|src|action|data-url|data-href)\s*=\s*["\']([^"\']+)["\']',
        html, re.IGNORECASE
    )
    # Also JavaScript links
    js_links = re.findall(r'(?:window\.location|location\.href)\s*=\s*["\']([^"\']+)["\']', html)
    all_links += js_links

    base_domain = urlparse(base_url).netloc

    for link in all_links:
        link = link.strip()
        if not link or link.startswith("#") or link.startswith("mailto:") or link.startswith("tel:"):
            continue
        if link.startswith("javascript:"):
            continue

        # Resolve relative URLs
        full_url = urljoin(base_url, link)
        parsed = urlparse(full_url)

        # Skip binary files
        ext = "." + full_url.split(".")[-1].lower() if "." in full_url.split("/")[-1] else ""
        if ext in SKIP_EXTENSIONS:
            continue

        if parsed.netloc == base_domain or parsed.netloc == "":
            if full_url not in internal:
                internal.append(full_url)
        else:
            if full_url not in external:
                external.append(full_url)

    return internal, external


def extract_forms(html: str, base_url: str) -> list:
    """Extract all HTML forms with their fields — targets for injection testing."""
    forms = []
    form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
    input_pattern = re.compile(
        r'<input[^>]*name=["\']([^"\']+)["\'][^>]*(?:type=["\']([^"\']+)["\'])?[^>]*>',
        re.IGNORECASE
    )
    action_pattern = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
    method_pattern = re.compile(r'method=["\']([^"\']+)["\']', re.IGNORECASE)

    for form_match in form_pattern.finditer(html):
        form_html = form_match.group(0)
        form_body = form_match.group(1)

        action_m = action_pattern.search(form_html)
        method_m = method_pattern.search(form_html)

        action = urljoin(base_url, action_m.group(1)) if action_m else base_url
        method = method_m.group(1).upper() if method_m else "GET"

        fields = []
        for inp in input_pattern.finditer(form_body):
            field_name = inp.group(1)
            field_type = inp.group(2) or "text"
            fields.append({"name": field_name, "type": field_type})

        # Also get textarea and select names
        for name in re.findall(r'<(?:textarea|select)[^>]*name=["\']([^"\']+)["\']', form_body, re.IGNORECASE):
            fields.append({"name": name, "type": "text"})

        if fields:
            forms.append({
                "action": action,
                "method": method,
                "fields": fields,
            })
            print_found(
                f"[FORM] {method} {action} → "
                f"fields: {[f['name'] for f in fields]}"
            )

    return forms


def extract_comments(html: str) -> list:
    """Extract HTML comments — devs often leave passwords and notes."""
    comments = []
    pattern = re.compile(r'<!--(.*?)-->', re.DOTALL)
    sensitive_keywords = ["password", "passwd", "todo", "fix", "hack", "bug",
                          "secret", "token", "key", "admin", "debug", "test",
                          "remove", "delete", "credentials", "auth"]

    for match in pattern.finditer(html):
        comment = match.group(1).strip()
        if len(comment) < 3:
            continue
        is_sensitive = any(kw in comment.lower() for kw in sensitive_keywords)
        comments.append({"content": comment[:300], "sensitive": is_sensitive})
        if is_sensitive:
            print_found(f"[COMMENT] 🚨 Sensitive comment: {comment[:150]}")

    return comments


def extract_data(html: str) -> dict:
    """Extract emails, phones, API paths, AWS buckets, etc."""
    data = {}
    for key, pattern in PATTERNS.items():
        matches = list(set(re.findall(pattern, html, re.DOTALL | re.IGNORECASE)))
        if matches:
            data[key] = matches[:50]  # Limit per type
            if key in ["emails", "api_paths", "aws_s3", "jwt_tokens", "ip_addresses"]:
                for m in matches[:5]:
                    val = m if isinstance(m, str) else m[0]
                    print_found(f"[{key.upper()}] {val[:100]}")
    return data


async def crawl_page(
    client: httpx.AsyncClient,
    url: str,
    domain: str,
    visited: set,
    results: dict,
    semaphore: asyncio.Semaphore,
    depth: int,
    max_depth: int,
):
    """Recursively crawl a single page."""
    if depth > max_depth or url in visited:
        return

    async with semaphore:
        visited.add(url)
        try:
            resp = await client.get(url, follow_redirects=True)
            if resp.status_code != 200:
                return

            content_type = resp.headers.get("content-type", "")
            if "html" not in content_type and "javascript" not in content_type:
                return

            html = resp.text
            print_info(f"[CRAWL] {url} [{resp.status_code}] ({len(html)} chars)")

            # Extract all data from page
            internal_links, external_links = extract_links(html, url, domain)
            forms = extract_forms(html, url)
            comments = extract_comments(html)
            page_data = extract_data(html)

            # Store results
            results["urls"].update(internal_links)
            results["external"].update(external_links)
            results["forms"].extend(forms)
            results["comments"].extend(comments)
            for key, values in page_data.items():
                results["data"].setdefault(key, [])
                results["data"][key].extend(values)

            # Recurse into internal links
            if depth < max_depth:
                tasks = [
                    crawl_page(client, link, domain, visited,
                               results, semaphore, depth + 1, max_depth)
                    for link in internal_links
                    if link not in visited
                ]
                await asyncio.gather(*tasks)

        except httpx.TimeoutException:
            pass
        except Exception:
            pass


async def _async_crawl(base_url: str, domain: str, max_depth: int,
                       concurrency: int) -> dict:
    results = {
        "urls":     set(),
        "external": set(),
        "forms":    [],
        "comments": [],
        "data":     {},
    }
    visited = set()
    semaphore = asyncio.Semaphore(concurrency)

    headers = {"User-Agent": "Mozilla/5.0 ReconTool/3.0"}
    async with httpx.AsyncClient(
        headers=headers, timeout=httpx.Timeout(10.0),
        verify=False,
        limits=httpx.Limits(max_connections=concurrency),
    ) as client:
        await crawl_page(client, base_url, domain, visited,
                         results, semaphore, 0, max_depth)

    # Convert sets to lists for JSON serialization
    results["urls"]     = list(results["urls"])
    results["external"] = list(results["external"])
    # Deduplicate data
    for key in results["data"]:
        results["data"][key] = list(set(results["data"][key]))

    return results


def run(target: str, port: int = 80, use_https: bool = False,
        max_depth: int = 3, concurrency: int = 20) -> dict:
    """Main entry point for web crawling."""
    scheme = "https" if use_https else "http"
    base_url = (
        f"{scheme}://{target}:{port}"
        if port not in [80, 443]
        else f"{scheme}://{target}"
    )

    # Extract domain
    domain = urlparse(base_url).netloc

    print_info(f"Crawling: {base_url} (depth={max_depth}, concurrency={concurrency})")
    print_warn("Extracting: URLs, forms, comments, emails, API paths, JS secrets...")

    try:
        results = asyncio.run(_async_crawl(base_url, domain, max_depth, concurrency))
    except KeyboardInterrupt:
        print_warn("Crawl interrupted.")
        return {}

    # Summary
    print_info(f"\nCrawl complete:")
    print_found(f"  Internal URLs  : {len(results['urls'])}")
    print_found(f"  External links : {len(results['external'])}")
    print_found(f"  Forms found    : {len(results['forms'])}")
    comments_sensitive = [c for c in results["comments"] if c.get("sensitive")]
    print_found(f"  HTML comments  : {len(results['comments'])} ({len(comments_sensitive)} sensitive)")
    for key, vals in results["data"].items():
        if vals:
            print_found(f"  {key.upper():15s}: {len(vals)} found")

    return results
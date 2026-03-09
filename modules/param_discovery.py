"""
Parameter Discovery Module
Finds hidden GET/POST parameters on web pages.
Technique: send requests with parameter wordlist and analyze response differences.
Finds things like ?debug=true, ?admin=1, ?file=, ?id=, ?cmd=
"""

import httpx
import asyncio
import threading
import hashlib
from utils.output import print_found, print_info, print_error, print_warn

_lock = threading.Lock()

# Common parameter names to test
DEFAULT_PARAMS = [
    # Debug / Admin
    "debug", "test", "admin", "dev", "development", "staging",
    "verbose", "trace", "log", "logging", "mode", "env",
    # Common functional params
    "id", "user", "username", "email", "name", "search", "query", "q",
    "page", "limit", "offset", "sort", "order", "filter",
    "file", "filename", "path", "dir", "folder", "url", "link", "src",
    "redirect", "return", "next", "back", "goto", "target",
    "token", "key", "secret", "api_key", "apikey", "auth", "session",
    "callback", "cb", "jsonp",
    "format", "type", "output", "view", "template", "lang", "locale",
    "action", "method", "cmd", "command", "exec", "run",
    "include", "load", "read", "open", "show", "display",
    "upload", "download", "export", "import",
    "from", "to", "start", "end", "date", "time",
    "host", "port", "ip", "domain",
    "ref", "source", "origin", "referer",
    "code", "error", "msg", "message", "status",
]


def get_response_fingerprint(resp: httpx.Response) -> str:
    """
    Create a fingerprint of a response to detect meaningful differences.
    We hash status_code + content_length + first 500 chars.
    """
    content_sample = resp.text[:500] if resp.text else ""
    fingerprint = f"{resp.status_code}:{len(resp.content)}:{content_sample}"
    return hashlib.md5(fingerprint.encode()).hexdigest()


async def discover_params_async(
        client: httpx.AsyncClient,
        url: str,
        baseline_fp: str,
        params: list[str],
        method: str,
        results: list,
        semaphore: asyncio.Semaphore,
):
    """
    Test each parameter and compare response to baseline.
    A different response = the server processed the parameter = it exists!
    """

    async def test_param(param):
        async with semaphore:
            try:
                test_value = "1"  # Generic test value
                if method.upper() == "GET":
                    resp = await client.get(url, params={param: test_value})
                else:
                    resp = await client.post(url, data={param: test_value})

                fp = get_response_fingerprint(resp)
                if fp != baseline_fp:
                    entry = {
                        "parameter": param,
                        "method": method.upper(),
                        "url": url,
                        "status": resp.status_code,
                        "response_size": len(resp.content),
                    }
                    with _lock:
                        results.append(entry)
                        print_found(
                            f"[PARAM] {method.upper()} ?{param}= → "
                            f"[{resp.status_code}] size:{len(resp.content)}"
                        )
            except Exception:
                pass

    tasks = [test_param(p) for p in params]
    await asyncio.gather(*tasks)


async def _async_param_discovery(
        base_url: str,
        paths: list[str],
        params: list[str],
        methods: list[str],
        concurrency: int,
) -> list[dict]:
    """Async engine for parameter discovery."""
    all_results = []
    semaphore = asyncio.Semaphore(concurrency)

    headers = {
        "User-Agent": "Mozilla/5.0 ReconTool/2.0",
        "Accept": "*/*",
    }

    async with httpx.AsyncClient(
            headers=headers,
            timeout=httpx.Timeout(8.0),
            verify=False,
            follow_redirects=False,
    ) as client:
        for path in paths:
            url = f"{base_url}{path}" if path.startswith("/") else f"{base_url}/{path}"
            print_info(f"Testing parameters on: {url}")

            for method in methods:
                try:
                    # Get baseline response (no extra params)
                    if method.upper() == "GET":
                        baseline = await client.get(url)
                    else:
                        baseline = await client.post(url)
                    baseline_fp = get_response_fingerprint(baseline)
                except Exception as e:
                    print_error(f"Cannot reach {url}: {e}")
                    continue

                results = []
                await discover_params_async(
                    client, url, baseline_fp, params, method, results, semaphore
                )
                all_results.extend(results)

    return all_results


def run(
        target: str,
        paths: list[str] = None,
        port: int = 80,
        use_https: bool = False,
        methods: list[str] = None,
        concurrency: int = 30,
        custom_params: list[str] = None,
) -> list[dict]:
    """
    Main entry point for parameter discovery.

    Args:
        target: hostname or IP
        paths: list of paths to test (default: just '/')
        port: web server port
        use_https: use HTTPS
        methods: HTTP methods to test (default: GET and POST)
        concurrency: parallel requests
        custom_params: additional params to test
    """
    if paths is None:
        paths = ["/"]
    if methods is None:
        methods = ["GET", "POST"]

    params = DEFAULT_PARAMS.copy()
    if custom_params:
        params.extend(custom_params)

    scheme = "https" if use_https else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        base_url = f"{scheme}://{target}"
    else:
        base_url = f"{scheme}://{target}:{port}"

    print_info(f"Parameter discovery on: {base_url}")
    print_info(f"Testing {len(params)} parameters × {len(methods)} methods × {len(paths)} paths")
    print_warn("Comparing responses to baseline — different response = parameter exists")

    try:
        results = asyncio.run(
            _async_param_discovery(base_url, paths, params, methods, concurrency)
        )
    except KeyboardInterrupt:
        print_warn("Parameter discovery interrupted.")
        return []

    if results:
        print_found(f"Total parameters discovered: {len(results)}")
    else:
        print_info("No hidden parameters found.")

    return results
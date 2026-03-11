"""
Parameter Discovery (Param Fuzzing) Module
Discovers hidden GET and POST parameters by:
1. Comparing responses to baseline (size/status difference = param exists)
2. Testing common param names from a large built-in wordlist
3. Mining parameters from crawled URLs and forms
4. Detecting reflection in responses (XSS surface)
5. Testing JSON body parameters for APIs
"""

import httpx
import asyncio
import threading
from lucuiec_recon.utils.output import print_found, print_info, print_warn

_lock = threading.Lock()

# Large built-in parameter wordlist
PARAM_WORDLIST = [
    # Auth / Session
    "id", "user", "username", "user_id", "userid", "uid",
    "email", "mail", "password", "passwd", "pass", "pwd",
    "token", "auth", "auth_token", "api_key", "apikey", "key",
    "session", "session_id", "sid", "jwt", "access_token",
    "refresh_token", "oauth_token", "secret",
    # Navigation / Routing
    "page", "p", "pg", "view", "tab", "section", "step",
    "action", "cmd", "command", "do", "op", "mode", "type",
    "module", "controller", "route", "path", "url", "uri",
    "redirect", "return", "next", "back", "goto", "redir",
    "continue", "dest", "destination", "target", "link",
    "location", "forward", "ref", "refer", "referrer",
    # Data / Content
    "q", "query", "search", "s", "keyword", "keywords", "term",
    "filter", "sort", "order", "orderby", "order_by", "by",
    "limit", "offset", "start", "end", "from", "to", "count",
    "size", "per_page", "page_size", "num", "number",
    "format", "output", "lang", "language", "locale",
    "callback", "jsonp", "json", "xml",
    # File / Upload
    "file", "filename", "filepath", "path", "dir", "directory",
    "include", "require", "load", "read", "open", "template",
    "upload", "download", "export", "import", "attachment",
    "document", "img", "image", "src", "source",
    # Debug / Dev
    "debug", "test", "demo", "preview", "draft",
    "verbose", "trace", "log", "show", "display",
    "admin", "superuser", "root", "su",
    "dev", "development", "staging", "prod",
    # Database
    "db", "database", "table", "column", "row", "record",
    "where", "having", "group", "join", "sql",
    # Misc
    "name", "title", "description", "content", "body", "text",
    "message", "msg", "comment", "data", "value", "val",
    "code", "hash", "checksum", "nonce", "csrf", "xsrf",
    "category", "tag", "label", "status", "state",
    "date", "time", "timestamp", "year", "month", "day",
    "price", "amount", "quantity", "qty", "total",
    "color", "colour", "width", "height",
    "lat", "lng", "latitude", "longitude", "zip", "country",
    "address", "city", "region", "phone", "mobile",
]


async def test_param_get(
    client, url, param, baseline_size, baseline_status, results, semaphore
):
    async with semaphore:
        sep = "&" if "?" in url else "?"
        test_url = f"{url}{sep}{param}=FUZZ_TEST_1337"
        try:
            resp = await client.get(test_url, follow_redirects=True)
            size      = len(resp.content)
            size_diff = abs(size - baseline_size)
            reflected = "FUZZ_TEST_1337" in resp.text

            if size_diff > 50 or resp.status_code != baseline_status or reflected:
                entry = {
                    "param":     param,
                    "method":    "GET",
                    "url":       test_url,
                    "status":    resp.status_code,
                    "size_diff": size_diff,
                    "reflected": reflected,
                }
                with _lock:
                    results.append(entry)
                    icon = "🚨" if reflected else "✅"
                    note = " [REFLECTED — XSS surface!]" if reflected else ""
                    print_found(
                        f"{icon} [GET] ?{param}= → [{resp.status_code}] "
                        f"diff:{size_diff}b{note}"
                    )
        except Exception:
            pass


async def test_param_post(
    client, url, param, baseline_size, results, semaphore
):
    async with semaphore:
        try:
            resp = await client.post(
                url, data={param: "FUZZ_TEST_1337"}, follow_redirects=True
            )
            size_diff = abs(len(resp.content) - baseline_size)
            reflected = "FUZZ_TEST_1337" in resp.text

            if size_diff > 50 or reflected:
                with _lock:
                    results.append({
                        "param":     param,
                        "method":    "POST",
                        "url":       url,
                        "status":    resp.status_code,
                        "size_diff": size_diff,
                        "reflected": reflected,
                    })
                    icon = "🚨" if reflected else "✅"
                    print_found(
                        f"{icon} [POST] {param}= → [{resp.status_code}] "
                        f"diff:{size_diff}b"
                        + (" [REFLECTED!]" if reflected else "")
                    )
        except Exception:
            pass


async def test_json_param(
    client, url, param, baseline_size, results, semaphore
):
    async with semaphore:
        try:
            import json as _json
            resp = await client.post(
                url,
                content=_json.dumps({param: "FUZZ_TEST_1337"}),
                headers={"Content-Type": "application/json"},
                follow_redirects=True,
            )
            size_diff = abs(len(resp.content) - baseline_size)
            reflected = "FUZZ_TEST_1337" in resp.text
            if size_diff > 50 or reflected:
                with _lock:
                    results.append({
                        "param":     param,
                        "method":    "JSON",
                        "url":       url,
                        "status":    resp.status_code,
                        "size_diff": size_diff,
                        "reflected": reflected,
                    })
                    print_found(
                        f"✅ [JSON] {param}: ... → [{resp.status_code}] "
                        f"diff:{size_diff}b"
                    )
        except Exception:
            pass


async def _async_param_fuzz(url, wordlist, test_post, test_json, concurrency):
    results  = []
    semaphore = asyncio.Semaphore(concurrency)
    headers  = {"User-Agent": "Mozilla/5.0 ReconTool/3.0"}

    async with httpx.AsyncClient(
        headers=headers, timeout=httpx.Timeout(8.0), verify=False,
        limits=httpx.Limits(max_connections=concurrency),
    ) as client:
        try:
            base_get  = await client.get(url, follow_redirects=True)
            base_post = await client.post(url, data={}, follow_redirects=True)
            bg_size   = len(base_get.content)
            bg_status = base_get.status_code
            bp_size   = len(base_post.content)
            print_info(f"Baseline GET:[{bg_status}] {bg_size}b  POST:{bp_size}b")
        except Exception:
            print_warn(f"Cannot reach {url} for baseline")
            return []

        tasks = [
            test_param_get(client, url, p, bg_size, bg_status, results, semaphore)
            for p in wordlist
        ]
        if test_post:
            tasks += [
                test_param_post(client, url, p, bp_size, results, semaphore)
                for p in wordlist
            ]
        if test_json:
            tasks += [
                test_json_param(client, url, p, bp_size, results, semaphore)
                for p in wordlist
            ]

        await asyncio.gather(*tasks)

    return results


def run(
    target, port=80, use_https=False,
    paths=None, wordlist=None,
    test_post=True, test_json=True,
    concurrency=40, extra_params=None,
):
    scheme   = "https" if use_https else "http"
    base_url = (
        f"{scheme}://{target}:{port}"
        if port not in [80, 443]
        else f"{scheme}://{target}"
    )

    if not paths:
        paths = ["/", "/search", "/api", "/api/v1", "/login", "/admin"]

    words = list(PARAM_WORDLIST)
    if wordlist:
        words = list(set(words + wordlist))
    if extra_params:
        words = list(set(words + extra_params))
        print_info(f"Added {len(extra_params)} params found by crawler/wayback")

    print_info(f"Param fuzzing: {base_url}")
    print_info(f"Testing {len(words)} params × {len(paths)} paths")
    print_info(f"Methods: GET{' + POST' if test_post else ''}{' + JSON' if test_json else ''}")

    all_results = []
    try:
        for path in paths:
            url = f"{base_url}{path}"
            print_info(f"Fuzzing: {url}")
            res = asyncio.run(
                _async_param_fuzz(url, words, test_post, test_json, concurrency)
            )
            all_results.extend(res)
    except KeyboardInterrupt:
        print_warn("Param fuzzing interrupted.")

    reflected   = [r for r in all_results if r.get("reflected")]
    get_params  = [r for r in all_results if r["method"] == "GET"]
    post_params = [r for r in all_results if r["method"] == "POST"]
    json_params = [r for r in all_results if r["method"] == "JSON"]

    print_info(f"\nParam discovery complete:")
    print_found(f"  GET  params : {len(get_params)}")
    print_found(f"  POST params : {len(post_params)}")
    print_found(f"  JSON params : {len(json_params)}")
    if reflected:
        print_found(f"  🚨 REFLECTED: {len(reflected)} — XSS surface!")

    return all_results
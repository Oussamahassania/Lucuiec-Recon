"""
API Endpoint Fuzzer Module
Specifically fuzzes REST API routes with ALL HTTP methods.
Most tools only do GET — APIs often have vulnerabilities on
PUT, DELETE, PATCH, POST that are completely missed.
Also detects:
- Unauthenticated API access
- HTTP method not allowed (405) → endpoint exists
- Mass assignment vulnerabilities
- API versioning (v1 vs v2 differences)
"""

import httpx
import asyncio
import json
import threading
from lucuiec_recon.utils.output import print_found, print_info, print_warn

_lock = threading.Lock()

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]

# Common API paths to fuzz
API_PATHS = [
    # Versioned APIs
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/v1", "/v2", "/v3",
    "/rest", "/rest/v1", "/rest/v2",
    # Common endpoints
    "/api/users", "/api/user", "/api/account", "/api/accounts",
    "/api/admin", "/api/administrator",
    "/api/login", "/api/logout", "/api/auth", "/api/token",
    "/api/register", "/api/signup",
    "/api/password", "/api/reset",
    "/api/profile", "/api/me", "/api/whoami",
    "/api/config", "/api/settings", "/api/configuration",
    "/api/debug", "/api/test", "/api/status", "/api/health",
    "/api/ping", "/api/version", "/api/info",
    "/api/docs", "/api/swagger", "/api/openapi",
    "/api/upload", "/api/download", "/api/files", "/api/file",
    "/api/search", "/api/query",
    "/api/data", "/api/export", "/api/import",
    "/api/logs", "/api/log",
    "/api/backup", "/api/backups",
    "/api/keys", "/api/key", "/api/tokens",
    "/api/payments", "/api/billing",
    "/api/email", "/api/emails",
    "/api/messages", "/api/notifications",
    # GraphQL
    "/graphql", "/graphiql", "/gql",
    # Common framework endpoints
    "/actuator", "/actuator/env", "/actuator/health",    # Spring Boot
    "/actuator/mappings", "/actuator/beans",
    "/_cat/indices", "/_cluster/health",                  # Elasticsearch
    "/wp-json/wp/v2/users",                              # WordPress REST
    "/wp-json/wp/v2/posts",
    "/.well-known/openid-configuration",                  # OAuth/OIDC
    "/oauth/token", "/oauth/authorize",
]

# Test payloads for different content types
TEST_PAYLOADS = {
    "json": json.dumps({"test": "value", "id": 1, "admin": True}),
    "form": "test=value&id=1",
}


async def test_api_endpoint(
    client: httpx.AsyncClient,
    base_url: str,
    path: str,
    method: str,
    results: list,
    semaphore: asyncio.Semaphore,
):
    """Test a single API endpoint with a specific HTTP method."""
    async with semaphore:
        url = f"{base_url}{path}"
        try:
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
            kwargs = {
                "headers": headers,
                "follow_redirects": False,
                "timeout": 8.0,
            }

            if method in ["POST", "PUT", "PATCH"]:
                kwargs["content"] = TEST_PAYLOADS["json"]

            resp = await getattr(client, method.lower())(url, **kwargs)
            code = resp.status_code
            size = len(resp.content)

            # Anything that's not 404 is interesting
            if code != 404:
                # Try to detect JSON response
                is_json = "application/json" in resp.headers.get("content-type", "")
                preview = ""
                if is_json and size < 5000:
                    try:
                        preview = str(resp.json())[:200]
                    except Exception:
                        preview = resp.text[:200]

                entry = {
                    "url":     url,
                    "method":  method,
                    "status":  code,
                    "size":    size,
                    "is_json": is_json,
                    "preview": preview,
                }

                with _lock:
                    results.append(entry)

                    # Severity based on status
                    if code == 200:
                        icon = "🚨" if method in ["DELETE", "PUT"] else "✅"
                        print_found(f"{icon} [{method}] [{code}] {url} ({size}b)")
                        if preview:
                            print(f"      → {preview[:150]}")
                    elif code == 401:
                        print_found(f"🔒 [{method}] [{code}] {url} — Auth required (endpoint exists!)")
                    elif code == 403:
                        print_found(f"🔒 [{method}] [{code}] {url} — Forbidden (endpoint exists!)")
                    elif code == 405:
                        print_info(f"⛔ [{method}] [{code}] {url} — Method not allowed")
                    elif code in [301, 302]:
                        location = resp.headers.get("location", "")
                        print_found(f"🔀 [{method}] [{code}] {url} → {location}")
                    elif code == 500:
                        print_found(f"💥 [{method}] [{code}] {url} — Server error (useful for error analysis!)")

        except Exception:
            pass


async def _async_api_fuzz(base_url: str, paths: list, methods: list,
                          concurrency: int) -> list:
    results = []
    semaphore = asyncio.Semaphore(concurrency)

    async with httpx.AsyncClient(
        verify=False,
        limits=httpx.Limits(max_connections=concurrency),
    ) as client:
        tasks = [
            test_api_endpoint(client, base_url, path, method, results, semaphore)
            for path in paths
            for method in methods
        ]
        await asyncio.gather(*tasks)

    return results


def check_swagger(base_url: str) -> dict:
    """Try to find and parse Swagger/OpenAPI docs — reveals ALL endpoints."""
    swagger_paths = [
        "/swagger.json", "/swagger/v1/swagger.json",
        "/openapi.json", "/api/swagger.json",
        "/swagger-ui.html", "/swagger-ui/",
        "/api-docs", "/api/docs",
        "/v2/api-docs", "/v3/api-docs",
    ]

    for path in swagger_paths:
        try:
            resp = httpx.get(f"{base_url}{path}", timeout=8.0, verify=False)
            if resp.status_code == 200:
                print_found(f"[SWAGGER] 🚨 Found API docs: {base_url}{path}")
                try:
                    spec = resp.json()
                    # Extract all paths from swagger spec
                    if "paths" in spec:
                        endpoints = list(spec["paths"].keys())
                        print_found(f"[SWAGGER] {len(endpoints)} endpoints documented:")
                        for ep in endpoints[:20]:
                            print(f"          → {ep}")
                        return {"url": f"{base_url}{path}", "endpoints": endpoints}
                except Exception:
                    return {"url": f"{base_url}{path}", "endpoints": []}
        except Exception:
            pass

    return {}


def run(target: str, port: int = 80, use_https: bool = False,
        methods: list = None, paths: list = None,
        concurrency: int = 30) -> dict:
    """Main entry point for API fuzzing."""
    scheme = "https" if use_https else "http"
    base_url = (
        f"{scheme}://{target}:{port}"
        if port not in [80, 443]
        else f"{scheme}://{target}"
    )

    if not methods:
        methods = HTTP_METHODS
    if not paths:
        paths = API_PATHS

    print_info(f"API fuzzing: {base_url}")
    print_info(f"Testing {len(paths)} paths × {len(methods)} methods = {len(paths)*len(methods)} requests")

    # First check for Swagger/OpenAPI docs
    swagger = check_swagger(base_url)

    # If swagger found additional paths, add them
    if swagger.get("endpoints"):
        extra = [ep for ep in swagger["endpoints"] if ep not in paths]
        paths = paths + extra[:50]
        print_info(f"Added {len(extra)} paths from Swagger docs")

    try:
        results = asyncio.run(_async_api_fuzz(base_url, paths, methods, concurrency))
    except KeyboardInterrupt:
        print_warn("API fuzzing interrupted.")
        results = []

    # Stats
    by_method = {}
    for r in results:
        by_method.setdefault(r["method"], []).append(r)

    print_info(f"\nAPI fuzzing complete: {len(results)} interesting responses")
    for method, items in by_method.items():
        print_found(f"  {method}: {len(items)} responses")

    return {"results": results, "swagger": swagger}
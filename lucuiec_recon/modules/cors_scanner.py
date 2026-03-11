"""
CORS Misconfiguration Scanner
Tests for dangerous CORS misconfigurations:
- Reflected arbitrary origins
- Null origin allowed
- Wildcard with credentials
- Trusted subdomain bypass
- Pre-domain bypass (evil.target.com)
These are common high/critical bug bounty findings.
"""

import httpx
from lucuiec_recon.utils.output import print_found, print_info

# Test origins to try
CORS_TEST_ORIGINS = [
    "https://evil.com",
    "https://attacker.com",
    "null",
    "https://evil.target.com",       # Subdomain bypass (filled in dynamically)
    "https://targetevil.com",        # Pre-domain bypass
    "https://evil.com.target.com",   # Suffix bypass
    "http://localhost",
    "http://127.0.0.1",
    "https://evil%60.com",           # URL encoding bypass
    "https://evil.com%0d%0a",        # CRLF injection
]

SEVERITY = {
    "reflected_any":         "CRITICAL",
    "null_origin":           "HIGH",
    "wildcard_credentials":  "CRITICAL",
    "subdomain_bypass":      "HIGH",
    "localhost_allowed":     "MEDIUM",
    "http_allowed":          "MEDIUM",
}


def check_cors_response(resp: httpx.Response, origin_sent: str) -> dict | None:
    """Analyze response headers for CORS misconfigurations."""
    acao = resp.headers.get("access-control-allow-origin", "")
    acac = resp.headers.get("access-control-allow-credentials", "").lower()
    acam = resp.headers.get("access-control-allow-methods", "")
    acah = resp.headers.get("access-control-allow-headers", "")

    if not acao:
        return None

    issues = []

    # Wildcard with credentials (impossible per spec but some servers do it wrong)
    if acao == "*" and acac == "true":
        issues.append({
            "type": "wildcard_credentials",
            "severity": "CRITICAL",
            "detail": "Wildcard origin with credentials=true — any site can make credentialed requests!",
        })

    # Arbitrary origin reflected
    if acao == origin_sent and acac == "true":
        issues.append({
            "type": "reflected_with_credentials",
            "severity": "CRITICAL",
            "detail": f"Origin '{origin_sent}' reflected AND credentials=true — account takeover possible!",
        })
    elif acao == origin_sent:
        issues.append({
            "type": "reflected_origin",
            "severity": "HIGH",
            "detail": f"Origin '{origin_sent}' reflected without credentials",
        })

    # Null origin allowed
    if acao == "null" and acac == "true":
        issues.append({
            "type": "null_origin_credentials",
            "severity": "CRITICAL",
            "detail": "Null origin with credentials=true — exploitable via sandboxed iframe!",
        })
    elif acao == "null":
        issues.append({
            "type": "null_origin",
            "severity": "HIGH",
            "detail": "Null origin allowed — exploitable via sandboxed iframe",
        })

    # Localhost allowed
    if "localhost" in acao or "127.0.0.1" in acao:
        issues.append({
            "type": "localhost_allowed",
            "severity": "MEDIUM",
            "detail": f"Localhost origin allowed: {acao}",
        })

    return {
        "origin_sent": origin_sent,
        "acao": acao,
        "acac": acac,
        "acam": acam,
        "issues": issues,
    } if issues else None


def scan_cors(target_url: str, domain: str = "") -> list:
    """
    Test CORS on a single URL with multiple malicious origins.
    """
    findings = []

    # Build domain-specific test origins
    test_origins = CORS_TEST_ORIGINS.copy()
    if domain:
        test_origins += [
            f"https://evil.{domain}",
            f"https://{domain}.evil.com",
            f"https://evil{domain}",
        ]

    headers_base = {
        "User-Agent": "Mozilla/5.0 ReconTool/3.0",
        "Accept": "application/json, text/html, */*",
    }

    for origin in test_origins:
        try:
            headers = {**headers_base, "Origin": origin}
            resp = httpx.get(
                target_url, headers=headers,
                timeout=8.0, verify=False,
                follow_redirects=True,
            )
            result = check_cors_response(resp, origin)
            if result and result["issues"]:
                findings.append({**result, "url": target_url})
                for issue in result["issues"]:
                    sev = issue["severity"]
                    icon = "🚨" if sev == "CRITICAL" else "⚠️ "
                    print_found(
                        f"{icon} [CORS][{sev}] {target_url}\n"
                        f"         Origin sent : {origin}\n"
                        f"         ACAO header : {result['acao']}\n"
                        f"         Credentials : {result['acac']}\n"
                        f"         Issue       : {issue['detail']}"
                    )
                    if sev == "CRITICAL":
                        print_found(
                            f"         PoC         : fetch('{target_url}', {{credentials:'include', "
                            f"headers:{{Origin:'{origin}'}}}})"
                        )
        except Exception:
            pass

    return findings


def run(target: str, port: int = 80, use_https: bool = False,
        domain: str = "", paths: list = None) -> list:
    """Main entry point for CORS scanning."""
    scheme = "https" if use_https else "http"
    base_url = (
        f"{scheme}://{target}:{port}"
        if port not in [80, 443]
        else f"{scheme}://{target}"
    )

    # Test paths — focus on API endpoints where CORS matters most
    if not paths:
        paths = [
            "/", "/api", "/api/v1", "/api/v2",
            "/graphql", "/rest", "/v1", "/v2",
        ]

    print_info(f"Testing CORS misconfigurations on {len(paths)} paths...")
    print_info(f"Using {len(CORS_TEST_ORIGINS)} malicious origins...")

    all_findings = []
    for path in paths:
        url = f"{base_url}{path}"
        findings = scan_cors(url, domain)
        all_findings.extend(findings)

    if not all_findings:
        print_info("No CORS misconfigurations found.")
    else:
        print_found(f"Total CORS issues: {len(all_findings)}")

    return all_findings
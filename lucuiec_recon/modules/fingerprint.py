"""
Technology Fingerprinting Module
Detects:
- Web server (Apache, Nginx, IIS...)
- Programming language / framework (PHP, Laravel, Django, WordPress...)
- WAF (Web Application Firewall) detection
- CMS detection
- Security headers analysis
All from HTTP headers + HTML body analysis — no external API needed.
"""

import httpx
import re
from lucuiec_recon.utils.output import print_found, print_info, print_error, print_warn

# ─── Fingerprint Signatures ───────────────────────────────────────────────────

# HTTP Header → Technology mapping
HEADER_SIGNATURES = {
    # Web Servers
    "Server": {
        r"Apache/([\d.]+)":         "Apache",
        r"nginx/([\d.]+)":          "Nginx",
        r"Microsoft-IIS/([\d.]+)":  "IIS",
        r"LiteSpeed":               "LiteSpeed",
        r"Caddy":                   "Caddy",
        r"openresty":               "OpenResty (Nginx+Lua)",
        r"gunicorn":                "Gunicorn (Python)",
        r"Werkzeug":                "Werkzeug (Python/Flask Dev)",
    },
    # Frameworks/Languages
    "X-Powered-By": {
        r"PHP/([\d.]+)":            "PHP",
        r"ASP\.NET":                "ASP.NET",
        r"Express":                 "Express.js (Node.js)",
        r"Next\.js":                "Next.js",
    },
    # WAF / CDN Detection
    "X-CDN":                        {".*": "CDN Detected"},
    "CF-Ray":                       {".*": "Cloudflare WAF/CDN"},
    "X-Sucuri-ID":                  {".*": "Sucuri WAF"},
    "X-Firewall-Protection":        {".*": "Firewall Protection"},
    "X-Cache":                      {".*": "Caching Layer"},
    "X-Varnish":                    {".*": "Varnish Cache"},
    # Security Headers
    "Strict-Transport-Security":    {".*": "HSTS Enabled"},
    "Content-Security-Policy":      {".*": "CSP Enabled"},
    "X-Frame-Options":              {".*": "Clickjacking Protection"},
    "X-XSS-Protection":             {".*": "XSS Protection Header"},
    "X-Content-Type-Options":       {".*": "MIME Sniffing Protection"},
}

# Cookie names → Technology
COOKIE_SIGNATURES = {
    r"PHPSESSID":           "PHP",
    r"JSESSIONID":          "Java (Tomcat/Spring)",
    r"ASP\.NET_SessionId":  "ASP.NET",
    r"laravel_session":     "Laravel (PHP)",
    r"django":              "Django (Python)",
    r"rack\.session":       "Ruby on Rails",
    r"wp-settings":         "WordPress",
    r"Drupal":              "Drupal CMS",
}

# HTML body signatures
BODY_SIGNATURES = {
    r"wp-content":                          "WordPress",
    r"wp-includes":                         "WordPress",
    r'content="WordPress':                  "WordPress",
    r"Joomla!":                             "Joomla CMS",
    r"Drupal.settings":                     "Drupal CMS",
    r"__VIEWSTATE":                         "ASP.NET WebForms",
    r"ng-version":                          "Angular",
    r'id="__next"':                         "Next.js",
    r"__nuxt":                              "Nuxt.js (Vue)",
    r"React\.createElement":               "React",
    r"django-admin":                        "Django Admin",
    r"laravel":                             "Laravel",
    r"Powered by <a[^>]+>phpBB":           "phpBB Forum",
    r"vBulletin":                           "vBulletin Forum",
    r'generator.*Wix\.com':                 "Wix",
    r'generator.*Squarespace':              "Squarespace",
    r"cdn\.shopify\.com":                   "Shopify",
    r"Magento":                             "Magento (eCommerce)",
    r"PrestaShop":                          "PrestaShop",
    r"<meta[^>]+generator[^>]+Bootstrap":  "Bootstrap CSS",
    r"jquery":                              "jQuery",
}

# Missing security headers (vulnerability indicators)
SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
]

# WAF detection via response behavior
WAF_SIGNATURES = {
    "cloudflare":   r"(?i)(cloudflare|cf-ray|__cfduid)",
    "akamai":       r"(?i)(akamai|x-akamai)",
    "incapsula":    r"(?i)(incapsula|visid_incap)",
    "sucuri":       r"(?i)(sucuri|x-sucuri)",
    "barracuda":    r"(?i)(barracuda)",
    "f5 big-ip":    r"(?i)(bigip|ts[a-f0-9]{8})",
    "modsecurity":  r"(?i)(mod_security|modsecurity)",
}


def detect_waf(headers: dict, body: str) -> list[str]:
    """Detect WAF by analyzing headers and response body."""
    wafs = []
    combined = str(headers).lower() + body[:2000].lower()
    for waf_name, pattern in WAF_SIGNATURES.items():
        if re.search(pattern, combined):
            wafs.append(waf_name.title())
    return wafs


def analyze_security_headers(headers: dict) -> dict:
    """Check which security headers are present/missing."""
    present = []
    missing = []
    for h in SECURITY_HEADERS:
        if h.lower() in {k.lower() for k in headers}:
            present.append(h)
        else:
            missing.append(h)
    return {"present": present, "missing": missing}


def fingerprint_response(headers: dict, body: str, cookies: dict) -> dict:
    """
    Analyze HTTP response to identify technologies.
    Returns dict of detected technologies by category.
    """
    tech = {
        "server": [],
        "language": [],
        "framework": [],
        "cms": [],
        "waf": [],
        "cdn": [],
        "javascript": [],
        "security_headers": {},
        "raw_headers": {},
    }

    # Collect raw interesting headers
    interesting = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
                   "X-Runtime", "X-Rack-Cache", "Via", "X-Cache"]
    for h in interesting:
        val = headers.get(h) or headers.get(h.lower())
        if val:
            tech["raw_headers"][h] = val

    # ── Header analysis ──
    for header_name, patterns in HEADER_SIGNATURES.items():
        header_val = headers.get(header_name) or headers.get(header_name.lower(), "")
        if not header_val:
            continue
        if isinstance(patterns, dict):
            for pattern, name in patterns.items():
                m = re.search(pattern, header_val, re.IGNORECASE)
                if m:
                    version = m.group(1) if m.lastindex else ""
                    label = f"{name} {version}".strip()
                    if "WAF" in name or "Cloudflare" in name or "Sucuri" in name:
                        tech["waf"].append(label)
                    elif "Cache" in name or "CDN" in name:
                        tech["cdn"].append(label)
                    elif "HSTS" in name or "CSP" in name or "Protection" in name:
                        pass  # handled by security headers
                    elif header_name == "X-Powered-By":
                        tech["language"].append(label)
                    else:
                        tech["server"].append(label)

    # ── Cookie analysis ──
    cookie_str = str(cookies)
    for pattern, name in COOKIE_SIGNATURES.items():
        if re.search(pattern, cookie_str, re.IGNORECASE):
            if "CMS" in name or "WordPress" in name or "Joomla" in name or "Drupal" in name:
                tech["cms"].append(name)
            else:
                tech["framework"].append(name)

    # ── Body analysis ──
    for pattern, name in BODY_SIGNATURES.items():
        if re.search(pattern, body, re.IGNORECASE):
            if "CMS" in name or "Forum" in name or "WordPress" in name or "Joomla" in name or "Drupal" in name or "Magento" in name or "Shopify" in name or "Wix" in name or "Squarespace" in name:
                tech["cms"].append(name)
            elif "jQuery" in name or "React" in name or "Angular" in name or "Vue" in name or "Next" in name or "Nuxt" in name or "Bootstrap" in name:
                tech["javascript"].append(name)
            else:
                tech["framework"].append(name)

    # ── WAF detection ──
    wafs = detect_waf(dict(headers), body)
    tech["waf"].extend(wafs)

    # ── Security headers ──
    tech["security_headers"] = analyze_security_headers(dict(headers))

    # Deduplicate
    for key in ["server", "language", "framework", "cms", "waf", "cdn", "javascript"]:
        tech[key] = list(dict.fromkeys(tech[key]))

    return tech


def run(target: str, port: int = 80, use_https: bool = False) -> dict:
    """
    Main entry point for technology fingerprinting.
    """
    scheme = "https" if use_https else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        base_url = f"{scheme}://{target}"
    else:
        base_url = f"{scheme}://{target}:{port}"

    print_info(f"Fingerprinting: {base_url}")

    try:
        headers_to_send = {
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ReconTool/2.0",
            "Accept": "text/html,application/xhtml+xml,*/*",
        }
        resp = httpx.get(
            base_url,
            headers=headers_to_send,
            follow_redirects=True,
            timeout=10.0,
            verify=False,
        )

        tech = fingerprint_response(
            dict(resp.headers),
            resp.text[:50000],
            dict(resp.cookies),
        )

        # ── Print results ──
        if tech["server"]:
            print_found(f"[TECH] Server:      {', '.join(tech['server'])}")
        if tech["language"]:
            print_found(f"[TECH] Language:    {', '.join(tech['language'])}")
        if tech["framework"]:
            print_found(f"[TECH] Framework:   {', '.join(tech['framework'])}")
        if tech["cms"]:
            print_found(f"[TECH] CMS:         {', '.join(tech['cms'])}")
        if tech["javascript"]:
            print_found(f"[TECH] JS Libs:     {', '.join(tech['javascript'])}")
        if tech["waf"]:
            print_found(f"[TECH] WAF/CDN:     {', '.join(tech['waf'])}")
            print_warn("⚠️  WAF detected — scans may be blocked or rate-limited!")
        else:
            print_info("No WAF detected.")

        # Security headers
        missing = tech["security_headers"].get("missing", [])
        present = tech["security_headers"].get("present", [])
        print_found(f"[SECURITY] Headers present: {len(present)}/{len(SECURITY_HEADERS)}")
        if missing:
            print_warn(f"[SECURITY] Missing headers: {', '.join(missing)}")

        if tech["raw_headers"]:
            print_info("Raw interesting headers:")
            for k, v in tech["raw_headers"].items():
                print(f"      {k}: {v}")

        return tech

    except httpx.ConnectError:
        print_error(f"Cannot connect to {base_url}")
    except Exception as e:
        print_error(f"Fingerprinting error: {e}")

    return {}
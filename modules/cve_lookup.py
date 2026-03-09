"""
CVE Correlation Module
After port scanning detects service versions, automatically query the
National Vulnerability Database (NVD) API for known CVEs.
This is what makes your tool unique — no common recon tool does this automatically.
"""

import requests
import time
from utils.output import print_found, print_info, print_error, print_warn

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# CVSS severity thresholds
SEVERITY = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
}

def get_severity_label(score: float) -> str:
    for label, (low, high) in SEVERITY.items():
        if low <= score <= high:
            return label
    return "INFO"


def query_nvd(keyword: str, max_results: int = 5) -> list[dict]:
    """
    Query the NVD API for CVEs matching a product/version keyword.
    Free API — no key needed (rate limited to 5 req/30s without key).
    """
    try:
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": max_results,
            "startIndex": 0,
        }
        resp = requests.get(NVD_API, params=params, timeout=15)
        if resp.status_code == 200:
            data = resp.json()
            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                cve_id = cve.get("id", "")
                desc_list = cve.get("descriptions", [])
                description = next(
                    (d["value"] for d in desc_list if d["lang"] == "en"), ""
                )

                # Extract CVSS score
                score = 0.0
                metrics = cve.get("metrics", {})
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        score = metrics[key][0].get("cvssData", {}).get("baseScore", 0.0)
                        break

                cves.append({
                    "id": cve_id,
                    "description": description[:300],
                    "score": score,
                    "severity": get_severity_label(score),
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                })
            return cves
    except Exception as e:
        print_error(f"NVD API error for '{keyword}': {e}")
    return []


def correlate_services(services: list[dict]) -> list[dict]:
    """
    Take nmap service results and look up CVEs for each service+version.
    Returns enriched list with CVE data attached.
    """
    results = []

    for svc in services:
        product = svc.get("product", "").strip()
        version = svc.get("version", "").strip()
        service_name = svc.get("service", "").strip()
        port = svc.get("port")

        # Build search keyword — prefer product+version, fallback to service name
        if product and version:
            keyword = f"{product} {version}"
        elif product:
            keyword = product
        elif service_name and service_name != "unknown":
            keyword = service_name
        else:
            results.append({**svc, "cves": []})
            continue

        print_info(f"Looking up CVEs for: {keyword} (port {port})")

        cves = query_nvd(keyword, max_results=5)

        # Print findings
        if cves:
            for cve in cves:
                score = cve["score"]
                sev = cve["severity"]
                # Color coding by severity
                if sev == "CRITICAL":
                    icon = "🔴"
                elif sev == "HIGH":
                    icon = "🟠"
                elif sev == "MEDIUM":
                    icon = "🟡"
                else:
                    icon = "🟢"
                print_found(
                    f"{icon} [{sev}] {cve['id']} (CVSS: {score}) — Port {port}/{service_name}"
                )
                print(f"      ↳ {cve['description'][:120]}...")
                print(f"      ↳ {cve['url']}")
        else:
            print_info(f"No CVEs found for {keyword}")

        results.append({**svc, "cves": cves})

        # NVD rate limit: 5 requests per 30 seconds without API key
        time.sleep(6)

    return results


def run(services: list[dict]) -> list[dict]:
    """
    Main entry point for CVE correlation.
    Input: list of service dicts from portscan module
    Output: same list enriched with CVE data
    """
    if not services:
        print_warn("No services to look up CVEs for.")
        return []

    print_info(f"Correlating {len(services)} services against NVD database...")
    print_warn("Rate limited to ~5 req/30s (NVD free tier). This may take a moment.")

    return correlate_services(services)
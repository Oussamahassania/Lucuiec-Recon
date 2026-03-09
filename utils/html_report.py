"""
HTML Report Generator
Generates a professional, color-coded security report.
"""

from datetime import datetime


def severity_color(severity: str) -> str:
    colors = {
        "CRITICAL": "#e74c3c",
        "HIGH": "#e67e22",
        "MEDIUM": "#f1c40f",
        "LOW": "#2ecc71",
        "INFO": "#3498db",
    }
    return colors.get(severity.upper(), "#95a5a6")


def status_badge(code: int) -> str:
    if code == 200:
        return f'<span class="badge badge-green">{code}</span>'
    elif code in [301, 302]:
        return f'<span class="badge badge-blue">{code}</span>'
    elif code in [401, 403]:
        return f'<span class="badge badge-orange">{code}</span>'
    elif code == 500:
        return f'<span class="badge badge-red">{code}</span>'
    return f'<span class="badge badge-grey">{code}</span>'


def generate_html_report(results: dict) -> str:
    target = results.get("target", "unknown")
    timestamp = results.get("timestamp", "")
    subdomains = results.get("subdomains", [])
    ports_data = results.get("ports", {})
    open_ports = ports_data.get("open_ports", [])
    services = ports_data.get("services", [])
    directories = results.get("directories", [])
    sensitive = results.get("sensitive_files", [])
    tech = results.get("technology", {})
    js_data = results.get("js_mining", {})
    params = results.get("parameters", [])
    cves = []
    for svc in services:
        for cve in svc.get("cves", []):
            cves.append({**cve, "port": svc.get("port"), "service": svc.get("service")})

    # Count critical findings
    critical_count = sum(1 for c in cves if c.get("severity") == "CRITICAL")
    high_count = sum(1 for c in cves if c.get("severity") == "HIGH")
    exposed_secrets = len(js_data.get("secrets", []))
    exposed_sensitive = sum(1 for s in sensitive if s.get("status") == 200)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report — {target}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #e6edf3; --text2: #8b949e;
    --green: #3fb950; --red: #f85149; --orange: #d29922;
    --blue: #58a6ff; --purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, sans-serif; padding: 24px; }}
  h1 {{ font-size: 2rem; color: var(--blue); margin-bottom: 4px; }}
  h2 {{ font-size: 1.1rem; color: var(--text2); font-weight: 400; margin-bottom: 32px; }}
  h3 {{ font-size: 1rem; color: var(--blue); margin-bottom: 12px; padding-bottom: 8px; border-bottom: 1px solid var(--border); }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 16px; margin-bottom: 32px; }}
  .stat {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; text-align: center; }}
  .stat .num {{ font-size: 2.5rem; font-weight: 700; }}
  .stat .label {{ color: var(--text2); font-size: 0.85rem; margin-top: 4px; }}
  .stat.red .num {{ color: var(--red); }}
  .stat.orange .num {{ color: var(--orange); }}
  .stat.green .num {{ color: var(--green); }}
  .stat.blue .num {{ color: var(--blue); }}
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 0.875rem; }}
  th {{ text-align: left; padding: 8px 12px; color: var(--text2); border-bottom: 1px solid var(--border); font-weight: 500; }}
  td {{ padding: 8px 12px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--bg3); }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.75rem; font-weight: 600; }}
  .badge-green {{ background: #1a4731; color: var(--green); }}
  .badge-red {{ background: #3d1f1f; color: var(--red); }}
  .badge-orange {{ background: #3d2b0f; color: var(--orange); }}
  .badge-blue {{ background: #1a2f4a; color: var(--blue); }}
  .badge-grey {{ background: var(--bg3); color: var(--text2); }}
  .severity {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: 700; }}
  .sev-CRITICAL {{ background: #3d1f1f; color: var(--red); }}
  .sev-HIGH {{ background: #3d2b0f; color: var(--orange); }}
  .sev-MEDIUM {{ background: #3d3a0f; color: #f1c40f; }}
  .sev-LOW {{ background: #1a4731; color: var(--green); }}
  .tag {{ display: inline-block; background: var(--bg3); border: 1px solid var(--border); border-radius: 4px; padding: 2px 8px; margin: 2px; font-size: 0.8rem; }}
  .section-title {{ font-size: 1.2rem; font-weight: 600; color: var(--text); margin: 32px 0 16px; display: flex; align-items: center; gap: 8px; }}
  .empty {{ color: var(--text2); font-style: italic; padding: 12px 0; }}
  code {{ background: var(--bg3); padding: 1px 6px; border-radius: 3px; font-family: monospace; font-size: 0.85rem; }}
  .alert {{ padding: 12px 16px; border-radius: 6px; margin-bottom: 16px; border-left: 4px solid; }}
  .alert-red {{ background: #2d1b1b; border-color: var(--red); }}
  .alert-orange {{ background: #2d2010; border-color: var(--orange); }}
</style>
</head>
<body>

<h1>🔍 Recon Report</h1>
<h2>Target: {target} &nbsp;|&nbsp; {timestamp}</h2>

<!-- STATS GRID -->
<div class="grid">
  <div class="stat {'red' if critical_count > 0 else 'green'}">
    <div class="num">{critical_count}</div>
    <div class="label">Critical CVEs</div>
  </div>
  <div class="stat {'orange' if high_count > 0 else 'green'}">
    <div class="num">{high_count}</div>
    <div class="label">High CVEs</div>
  </div>
  <div class="stat blue">
    <div class="num">{len(subdomains)}</div>
    <div class="label">Subdomains</div>
  </div>
  <div class="stat blue">
    <div class="num">{len(open_ports)}</div>
    <div class="label">Open Ports</div>
  </div>
  <div class="stat {'red' if exposed_sensitive > 0 else 'green'}">
    <div class="num">{exposed_sensitive}</div>
    <div class="label">Exposed Files</div>
  </div>
  <div class="stat {'red' if exposed_secrets > 0 else 'green'}">
    <div class="num">{exposed_secrets}</div>
    <div class="label">JS Secrets</div>
  </div>
  <div class="stat blue">
    <div class="num">{len(directories)}</div>
    <div class="label">Directories</div>
  </div>
  <div class="stat blue">
    <div class="num">{len(params)}</div>
    <div class="label">Parameters</div>
  </div>
</div>

<!-- ALERTS -->
{'<div class="alert alert-red">🚨 <strong>CRITICAL:</strong> ' + str(critical_count) + ' critical CVEs found. Immediate attention required.</div>' if critical_count > 0 else ''}
{'<div class="alert alert-orange">⚠️ <strong>WARNING:</strong> ' + str(exposed_secrets) + ' secrets/tokens found in JavaScript files.</div>' if exposed_secrets > 0 else ''}
{'<div class="alert alert-red">🚨 <strong>EXPOSED:</strong> ' + str(exposed_sensitive) + ' sensitive files accessible (200 OK).</div>' if exposed_sensitive > 0 else ''}

<!-- TECHNOLOGY -->
<div class="section-title">🖥️ Technology Stack</div>
<div class="card">
{''.join([f'<strong>{k.title()}:</strong> ' + ''.join([f'<span class="tag">{v}</span>' for v in vals]) + '<br>' for k, vals in tech.items() if isinstance(vals, list) and vals]) if tech else '<p class="empty">No technology detected</p>'}
{('<br><strong>Missing Security Headers:</strong> ' + ''.join([f'<span class="tag" style="border-color:#e74c3c;color:#e74c3c">{h}</span>' for h in tech.get("security_headers", {}).get("missing", [])])) if tech.get("security_headers", {}).get("missing") else ''}
</div>

<!-- CVEs -->
<div class="section-title">🔴 CVE Findings ({len(cves)} total)</div>
<div class="card">
{"".join([f'''<table><thead><tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Port/Service</th><th>Description</th></tr></thead><tbody>''' + "".join([f'<tr><td><a href="{c["url"]}" style="color:var(--blue)">{c["id"]}</a></td><td><span class="severity sev-{c["severity"]}">{c["severity"]}</span></td><td>{c["score"]}</td><td>{c.get("port","")}/{c.get("service","")}</td><td>{c["description"][:150]}</td></tr>' for c in cves]) + '</tbody></table>']) if cves else '<p class="empty">No CVEs found</p>'}
</div>

<!-- OPEN PORTS & SERVICES -->
<div class="section-title">🔌 Open Ports & Services ({len(services)} detected)</div>
<div class="card">
{f'<table><thead><tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th><th>CVEs</th></tr></thead><tbody>' + "".join([f'<tr><td><code>{s["port"]}</code></td><td>{s.get("protocol","")}</td><td>{s.get("service","")}</td><td>{s.get("product","")}</td><td>{s.get("version","")}</td><td>{len(s.get("cves",[]))}</td></tr>' for s in services]) + '</tbody></table>' if services else '<p class="empty">No service data (run with nmap enabled)</p>'}
</div>

<!-- SUBDOMAINS -->
<div class="section-title">🌐 Subdomains ({len(subdomains)} found)</div>
<div class="card">
{f'<table><thead><tr><th>Subdomain</th><th>IP Addresses</th></tr></thead><tbody>' + "".join([f'<tr><td><code>{s["subdomain"]}</code></td><td>{", ".join(s["ips"])}</td></tr>' for s in subdomains]) + '</tbody></table>' if subdomains else '<p class="empty">No subdomains found</p>'}
</div>

<!-- SENSITIVE FILES -->
<div class="section-title">🔑 Sensitive Files ({len(sensitive)} found)</div>
<div class="card">
{f'<table><thead><tr><th>Status</th><th>URL</th><th>Size</th><th>Category</th></tr></thead><tbody>' + "".join([f'<tr><td>{status_badge(s["status"])}</td><td><code>{s["url"]}</code></td><td>{s["size"]}b</td><td>{s["category"]}</td></tr>' for s in sensitive]) + '</tbody></table>' if sensitive else '<p class="empty">No sensitive files found</p>'}
</div>

<!-- JS MINING -->
<div class="section-title">⚙️ JavaScript Mining</div>
<div class="card">
<h3>API Endpoints Found ({len(js_data.get("endpoints", []))})</h3>
{"".join([f'<code style="display:block;margin:4px 0">{ep}</code>' for ep in js_data.get("endpoints", [])[:30]]) or '<p class="empty">No endpoints found</p>'}
<br>
<h3>Secrets & Sensitive Data ({len(js_data.get("secrets", []))})</h3>
{f'<table><thead><tr><th>Type</th><th>Value</th><th>Line</th><th>File</th></tr></thead><tbody>' + "".join([f'<tr><td><span class="badge badge-red">{s["type"]}</span></td><td><code>{s["value"][:80]}</code></td><td>{s["line"]}</td><td>{s["source"].split("/")[-1]}</td></tr>' for s in js_data.get("secrets", [])]) + '</tbody></table>' if js_data.get("secrets") else '<p class="empty">No secrets found in JS files</p>'}
</div>

<!-- PARAMETERS -->
<div class="section-title">🎯 Hidden Parameters ({len(params)} found)</div>
<div class="card">
{f'<table><thead><tr><th>Parameter</th><th>Method</th><th>URL</th><th>Status</th></tr></thead><tbody>' + "".join([f'<tr><td><code>?{p["parameter"]}=</code></td><td><span class="badge badge-blue">{p["method"]}</span></td><td>{p["url"]}</td><td>{status_badge(p["status"])}</td></tr>' for p in params]) + '</tbody></table>' if params else '<p class="empty">No hidden parameters found</p>'}
</div>

<!-- DIRECTORIES -->
<div class="section-title">📁 Directories & Files ({len(directories)} found)</div>
<div class="card">
{f'<table><thead><tr><th>Status</th><th>URL</th><th>Size</th></tr></thead><tbody>' + "".join([f'<tr><td>{status_badge(d["status"])}</td><td><code>{d["url"]}</code></td><td>{d["size"]}b</td></tr>' for d in directories[:100]]) + '</tbody></table>' if directories else '<p class="empty">No directories found</p>'}
</div>

<div style="text-align:center;color:var(--text2);margin-top:40px;font-size:0.8rem">
  Generated by ReconTool v2.0 &nbsp;|&nbsp; For authorized security testing only &nbsp;|&nbsp; {timestamp}
</div>

</body>
</html>"""

    return html


def save_html_report(results: dict, output_dir: str = "results") -> str:
    """Save HTML report to file and return the path."""
    import os
    os.makedirs(output_dir, exist_ok=True)
    target = results.get("target", "scan").replace(".", "_")
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = f"{output_dir}/{target}_{timestamp}_report.html"
    html = generate_html_report(results)
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    return path
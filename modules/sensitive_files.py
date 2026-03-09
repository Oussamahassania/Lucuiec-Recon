"""
Sensitive File Hunter Module
Specifically hunts for files that win bug bounties:
.env, config files, backup files, git exposure, credentials, cloud configs.
Goes far beyond generic directory scanning.
"""

import httpx
import asyncio
import threading
from utils.output import print_found, print_info, print_error, print_warn

_lock = threading.Lock()

# Categorized sensitive file targets
SENSITIVE_FILES = {
    "🔑 Credentials & Secrets": [
        ".env", ".env.local", ".env.production", ".env.development",
        ".env.backup", ".env.old", ".env.bak", ".env.example",
        "config.php", "config.yml", "config.yaml", "config.json",
        "configuration.php", "settings.py", "settings.php",
        "database.yml", "database.php", "db.php", "db.json",
        "credentials.json", "credentials.xml", "secrets.json",
        "wp-config.php", "wp-config.php.bak", "wp-config.php.old",
        "LocalSettings.php",  # MediaWiki
    ],
    "📁 Git & Version Control": [
        ".git/config", ".git/HEAD", ".git/index",
        ".git/COMMIT_EDITMSG", ".git/logs/HEAD",
        ".gitignore", ".gitconfig",
        ".svn/entries", ".svn/wc.db",
        ".hg/hgrc",
    ],
    "💾 Backup Files": [
        "backup.zip", "backup.tar.gz", "backup.sql", "backup.sql.gz",
        "db_backup.sql", "database.sql", "dump.sql",
        "site.zip", "website.zip", "www.zip", "html.zip",
        "backup/backup.zip", "backups/backup.zip",
        "old.zip", "archive.zip",
        "index.php.bak", "index.php.old", "index.bak",
    ],
    "🔍 Information Disclosure": [
        "phpinfo.php", "info.php", "test.php", "php_info.php",
        "server-status", "server-info",  # Apache status pages
        "web.config",  # IIS config (can expose secrets)
        "elmah.axd",  # ASP.NET error log
        "trace.axd",  # ASP.NET trace
        "README.md", "README.txt", "CHANGELOG.md", "CHANGELOG.txt",
        "INSTALL.md", "INSTALL.txt", "TODO.md",
        "robots.txt", "sitemap.xml", "crossdomain.xml",
        "security.txt", ".well-known/security.txt",
    ],
    "☁️ Cloud & DevOps": [
        "docker-compose.yml", "docker-compose.yaml",
        "Dockerfile", ".dockerignore",
        "kubernetes.yml", "k8s.yml",
        "terraform.tfstate", "terraform.tfvars",
        ".aws/credentials", "aws.json",
        "Jenkinsfile", ".travis.yml", ".circleci/config.yml",
        "ansible.cfg", "hosts",
    ],
    "🔐 Private Keys & Certs": [
        "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
        "private.key", "private.pem", "server.key",
        "*.p12", "*.pfx", "cert.pem", "ca.pem",
        "ssl.key", "ssl.crt",
    ],
    "📊 Logs & Debug": [
        "error.log", "access.log", "debug.log", "app.log",
        "logs/error.log", "logs/access.log", "var/log/error.log",
        "storage/logs/laravel.log",  # Laravel
        "application.log", "server.log",
        ".htaccess", ".htpasswd",
    ],
    "🗃️ Admin & Panels": [
        "admin/", "administrator/", "admin.php", "admin.html",
        "phpmyadmin/", "pma/", "mysql/",
        "adminer.php", "adminer/",
        "console/", "dashboard/",
        "manager/html",  # Tomcat manager
        "solr/", "elasticsearch/",
        "kibana/",
    ],
}

# Flatten with category labels
def get_all_targets() -> list[tuple[str, str]]:
    """Returns list of (category, path) tuples."""
    targets = []
    for category, paths in SENSITIVE_FILES.items():
        for path in paths:
            targets.append((category, path))
    return targets


async def check_sensitive_file(
    client: httpx.AsyncClient,
    base_url: str,
    category: str,
    path: str,
    results: list,
    semaphore: asyncio.Semaphore,
):
    """Check if a sensitive file exists and is accessible."""
    async with semaphore:
        url = f"{base_url}/{path}".replace("//", "/").replace(":/", "://")
        try:
            resp = await client.get(url, follow_redirects=False)
            code = resp.status_code
            size = len(resp.content)

            # Interesting status codes
            if code in [200, 206, 301, 302, 401, 403, 500]:
                # Extra check: 200 responses should have content (not just redirect pages)
                if code == 200 and size < 20:
                    return  # Likely empty/default page

                severity = "🚨 CRITICAL" if code == 200 else "⚠️  EXISTS"
                if code in [401, 403]:
                    severity = "🔒 PROTECTED"
                elif code == 500:
                    severity = "💥 ERROR"

                entry = {
                    "category": category,
                    "url": url,
                    "path": path,
                    "status": code,
                    "size": size,
                    "severity": severity,
                }
                with _lock:
                    results.append(entry)
                    print_found(
                        f"{severity} [{code}] {url} ({size} bytes) — {category}"
                    )

                    # Show preview for critical exposed files
                    if code == 200 and any(x in path for x in [".env", "config", "backup", "id_rsa", "credentials"]):
                        preview = resp.text[:200].replace("\n", " ")
                        print_warn(f"      Preview: {preview[:150]}...")

        except Exception:
            pass


async def _async_sensitive_scan(base_url: str, concurrency: int) -> list[dict]:
    """Async engine for sensitive file hunting."""
    results = []
    targets = get_all_targets()
    semaphore = asyncio.Semaphore(concurrency)

    headers = {"User-Agent": "Mozilla/5.0 ReconTool/2.0"}

    async with httpx.AsyncClient(
        headers=headers,
        timeout=httpx.Timeout(6.0),
        verify=False,
        limits=httpx.Limits(max_connections=concurrency),
    ) as client:
        tasks = [
            check_sensitive_file(client, base_url, cat, path, results, semaphore)
            for cat, path in targets
        ]
        await asyncio.gather(*tasks)

    return results


def run(target: str, port: int = 80, use_https: bool = False, concurrency: int = 40) -> list[dict]:
    """
    Main entry point for sensitive file hunting.
    """
    scheme = "https" if use_https else "http"
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        base_url = f"{scheme}://{target}"
    else:
        base_url = f"{scheme}://{target}:{port}"

    targets = get_all_targets()
    print_info(f"Hunting {len(targets)} sensitive file patterns on: {base_url}")
    print_warn("Focus: credentials, backups, git exposure, cloud configs, keys")

    try:
        results = asyncio.run(_async_sensitive_scan(base_url, concurrency))
    except KeyboardInterrupt:
        print_warn("Sensitive file scan interrupted.")
        return []

    # Summary by category
    if results:
        by_cat = {}
        for r in results:
            cat = r["category"]
            by_cat.setdefault(cat, []).append(r)

        print_found(f"\nSensitive files found: {len(results)}")
        for cat, items in by_cat.items():
            print(f"  {cat}: {len(items)} found")
    else:
        print_info("No sensitive files found (good sign, or well-protected target).")

    return results
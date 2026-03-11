<div align="center">

# 🔍 Lucuiec-Recon

### Ultimate Web Hacking Recon Framework

![Python](https://img.shields.io/badge/Python-3.8+-blue?style=for-the-badge&logo=python)
![Version](https://img.shields.io/badge/Version-3.0.0-red?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows%20%7C%20Mac-orange?style=for-the-badge)

> ⚠️ **For authorized use ONLY** — Bug Bounty · TryHackMe · HackTheBox · CTF Labs · Your own targets

</div>

---

## 📦 Installation

### One command install from GitHub
```bash
pip install git+https://github.com/Oussamahassania/LucuiecRecon.git
```

### Run it from anywhere
```bash
lucuiec-recon -t 10.10.10.5 --all
lucuiec-recon -t target.com --dirs --recursive
lucuiec-recon --help
```

### Install for development (clone + edit)
```bash
git clone https://github.com/Oussamahassania/LucuiecRecon.git
cd LucuiecRecon
pip install -e .
```

### Kali Linux
```bash
git clone https://github.com/Oussamahassania/LucuiecRecon.git
cd LucuiecRecon
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python lucuiec_recon/main.py -t 10.10.10.5 --all
```

---

## 🗂️ Project Structure

```
LucuiecRecon/
│
├── lucuiec_recon/                ← Main package
│   ├── __init__.py
│   ├── main.py                   ← Entry point
│   │
│   ├── modules/
│   │   ├── subdomain.py          ← 🌍 DNS brute-force + crt.sh passive recon
│   │   ├── portscan.py           ← 🔌 TCP port scan + nmap service detection
│   │   ├── dirscan.py            ← 📁 Dir brute-force + recursive + progress bar
│   │   ├── fingerprint.py        ← 🖥️  Server / CMS / WAF / Framework detection
│   │   ├── cve_lookup.py         ← 🔎 Auto CVE lookup from NVD API
│   │   ├── js_miner.py           ← ⛏️  Extract secrets/endpoints from JS files
│   │   ├── sensitive_files.py    ← 🔑 Hunt .env, backups, .git, configs
│   │   ├── param_discovery.py    ← 🎯 GET + POST + JSON param fuzzing
│   │   ├── vhost_fuzzer.py       ← 🌐 Virtual host discovery
│   │   ├── cors_scanner.py       ← 🔀 CORS misconfiguration scanner
│   │   ├── crawler.py            ← 🕷️  Full web crawler + URL/form extractor
│   │   ├── wayback.py            ← 📼 Wayback Machine historical recon
│   │   ├── api_fuzzer.py         ← 🔌 REST API endpoint + HTTP method fuzzer
│   │   └── vuln_scanner.py       ← 💉 SQLi / XSS / LFI / Redirect / SSTI
│   │
│   ├── utils/
│   │   ├── output.py             ← 🎨 Colored output + save results
│   │   └── html_report.py        ← 📊 Dark-themed HTML report
│   │
│   └── wordlists/
│       ├── subdomains.txt
│       └── directories.txt
│
├── setup.py                      ← pip install config
├── setup.cfg
├── MANIFEST.in
├── requirements.txt
└── README.md
```

---

## ⚡ Usage

### Full scan — all 14 modules
```bash
lucuiec-recon -t target.com --all
lucuiec-recon -t 10.10.10.5 --all
```

### Full scan with HTTPS
```bash
lucuiec-recon -t target.com --all --https --web-port 443
```

### Directory scan — with progress bar
```bash
# Basic
lucuiec-recon -t lab.thm --dirs

# Scan a specific path (e.g. target.com/admin)
lucuiec-recon -t lab.thm --dirs --base-path /admin

# Recursive mode — like dirbuster -r
lucuiec-recon -t lab.thm --dirs --recursive

# Recursive with depth limit
lucuiec-recon -t lab.thm --dirs --recursive --depth 4

# Custom wordlist + extensions
lucuiec-recon -t lab.thm --dirs \
  --dir-wordlist /usr/share/seclists/Discovery/Web-Content/common.txt \
  --extensions .php,.txt,.bak,.zip

# Ultra fast (300 threads)
lucuiec-recon -t lab.thm --dirs --dir-threads 300
```

### Web crawler + URL finder
```bash
lucuiec-recon -t target.com --crawl
lucuiec-recon -t target.com --crawl --crawl-depth 5
```

### Vulnerability scan (SQLi, XSS, LFI, Redirect)
```bash
# Best: crawl first to find URLs, then scan them
lucuiec-recon -t target.com --crawl --vulns
```

### CORS misconfiguration scan
```bash
lucuiec-recon -t target.com --cors --vhost-domain target.com
```

### Virtual host fuzzing
```bash
lucuiec-recon -t 10.10.10.5 --vhost --vhost-domain target.com
```

### API endpoint fuzzer
```bash
lucuiec-recon -t target.com --api
```

### Wayback Machine — passive recon
```bash
lucuiec-recon -t target.com --wayback --vhost-domain target.com
```

### Parameter discovery (GET + POST + JSON)
```bash
lucuiec-recon -t target.com --params
```

### Subdomain enumeration
```bash
# With built-in wordlist
lucuiec-recon -t target.com --subdomains

# With SecLists
lucuiec-recon -t target.com --subdomains \
  --sub-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

### Port scan + service detection
```bash
lucuiec-recon -t 10.10.10.5 --ports
lucuiec-recon -t 10.10.10.5 --ports --port-range 1-65535
```

### Skip connectivity check (VPN issues)
```bash
lucuiec-recon -t 10.10.10.5 --all --force
```

### Save results to custom directory
```bash
lucuiec-recon -t target.com --all -o /tmp/myrecon
```

---

## 🧠 All 14 Modules

| # | Module | Description |
|---|--------|-------------|
| 1 | **Subdomain** | crt.sh passive + DNS brute-force |
| 2 | **Port Scan** | TCP scan + banner grab + nmap -sV -sC |
| 3 | **Dir Scan** | Async brute-force + recursive + live progress bar |
| 4 | **Fingerprint** | Server / CMS / WAF / Framework detection |
| 5 | **CVE Lookup** | Maps service versions → CVEs via NVD API |
| 6 | **JS Miner** | Extracts API keys, JWT tokens, endpoints from JS |
| 7 | **Sensitive Files** | 100+ patterns: .env, .git, backups, SSH keys |
| 8 | **Param Discovery** | GET + POST + JSON fuzzing, reflection detection |
| 9 | **VHost Fuzzer** | Finds hidden virtual hosts via Host header |
| 10 | **CORS Scanner** | Detects CRITICAL misconfigs — account takeover |
| 11 | **Web Crawler** | URLs, forms, comments, emails, API paths, secrets |
| 12 | **Wayback Machine** | Historical URLs — finds deleted admin panels |
| 13 | **API Fuzzer** | 100 paths × 7 HTTP methods + Swagger detection |
| 14 | **Vuln Scanner** | SQLi, XSS, LFI, Open Redirect, SSTI |

---

## 🎯 Best Combinations

### TryHackMe / HackTheBox machine
```bash
# Full scan
lucuiec-recon -t 10.10.10.5 --all --vhost-domain target.thm

# Web focused
lucuiec-recon -t 10.10.10.5 --dirs --fingerprint --crawl --api --vulns

# Quick dir scan on a specific path
lucuiec-recon -t 10.10.10.5 --dirs --base-path /secret --recursive
```

### Bug Bounty
```bash
# Maximum passive recon first (no touching the target)
lucuiec-recon -t target.com --subdomains --wayback --vhost-domain target.com

# Then active
lucuiec-recon -t target.com --all --vhost-domain target.com \
  --sub-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --dir-wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

### Pure web attack surface
```bash
lucuiec-recon -t target.com --crawl --api --cors --params --vulns \
  --vhost-domain target.com --crawl-depth 5
```

---

## 📊 Output Files

Every scan auto-saves to `results/`:

| File | Contents |
|------|----------|
| `target_timestamp.json` | Full structured data — all findings |
| `target_timestamp.txt` | Human-readable text summary |
| `target_timestamp_report.html` | Dark-themed HTML report |

---

## 🎨 Output Color Guide

| Color | Prefix | Meaning |
|-------|--------|---------|
| 🔴 Red Bold | `[!!!]` | Critical — exploit this first |
| 🟢 Green | `[+]` | Found — noteworthy item |
| 🔵 Blue | `[*]` | Info — general output |
| 🟡 Yellow | `[-]` | Warning — investigate manually |
| 🔴 Red | `[!]` | Error |

---

## 📋 Requirements

```
python >= 3.8
httpx >= 0.25.0
requests >= 2.31.0
dnspython >= 2.4.0
colorama >= 0.4.6
python-nmap >= 0.7.1
nmap (system package)
```

Install system nmap:
```bash
sudo apt install nmap -y       # Kali / Debian
brew install nmap              # macOS
```

---

## ⚖️ Legal Notice

This tool is for **authorized penetration testing and security research only.**

Running this against systems you don't own or have **explicit written permission** to test is **illegal** and may result in criminal prosecution.

**Safe environments:**

[![TryHackMe](https://img.shields.io/badge/TryHackMe-red?style=flat-square)](https://tryhackme.com)
[![HackTheBox](https://img.shields.io/badge/HackTheBox-green?style=flat-square)](https://hackthebox.com)
[![VulnHub](https://img.shields.io/badge/VulnHub-blue?style=flat-square)](https://vulnhub.com)
[![BugCrowd](https://img.shields.io/badge/BugCrowd-orange?style=flat-square)](https://bugcrowd.com)
[![HackerOne](https://img.shields.io/badge/HackerOne-white?style=flat-square)](https://hackerone.com)

---

## 👤 Author

**Oussamahassania** — [@Oussamahassania](https://github.com/Oussamahassania)

---

<div align="center">
⭐ Star this repo if it helped you!
</div>
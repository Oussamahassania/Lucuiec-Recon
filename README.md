# 🔍 ReconTool — Educational Recon Framework

> ⚠️ **For educational use ONLY. Only scan targets you have explicit permission to test.**  
> Legal platforms: TryHackMe, HackTheBox, your own machines.

---

## 📦 Installation

```bash
# 1. Install system dependency (nmap)
sudo apt install nmap -y        # Kali/Ubuntu/Debian
# brew install nmap             # macOS

# 2. Install Python dependencies
pip install -r requirements.txt

# 3. Run it!
python main.py --help
```

---

## 🚀 Usage Examples

### Full scan (all 3 modules)
```bash
python main.py -t 10.10.10.5 --all
```

### Subdomain enumeration only
```bash
python main.py -t example.com --subdomains
```

### Port scan — top common ports
```bash
python main.py -t 10.10.10.5 --ports
```

### Port scan — full range (all 65535 ports, slow but thorough)
```bash
python main.py -t 10.10.10.5 --ports --port-range 1-65535
```

### Port scan — specific ports only
```bash
python main.py -t 10.10.10.5 --ports --port-range 22,80,443,8080,8443
```

### Directory scan on default port 80
```bash
python main.py -t 10.10.10.5 --dirs
```

### Directory scan on custom port (e.g. 8080)
```bash
python main.py -t 10.10.10.5 --dirs --web-port 8080
```

### Directory scan with HTTPS
```bash
python main.py -t 10.10.10.5 --dirs --https --web-port 443
```

### Directory scan with specific extensions
```bash
python main.py -t 10.10.10.5 --dirs --extensions ".php,.txt,.bak,.zip"
```

### Fast scan (skip nmap service detection)
```bash
python main.py -t 10.10.10.5 --ports --dirs --no-nmap
```

### Custom wordlists (recommended: use SecLists)
```bash
python main.py -t 10.10.10.5 --all \
  --sub-wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --dir-wordlist /usr/share/seclists/Discovery/Web-Content/common.txt
```

---

## 📁 Project Structure

```
recon_tool/
├── main.py              ← CLI entry point (start here)
├── requirements.txt
├── modules/
│   ├── subdomain.py     ← DNS brute-force + crt.sh passive recon
│   ├── portscan.py      ← TCP socket scan + nmap service detection
│   └── dirscan.py       ← Async HTTP directory brute-force
├── utils/
│   └── output.py        ← Colored output + JSON/TXT report saving
├── wordlists/
│   ├── subdomains.txt   ← Mini bundled list (replace with SecLists)
│   └── directories.txt  ← Mini bundled list (replace with SecLists)
└── results/             ← Scan reports saved here (auto-created)
```

---

## 🧠 What Each Module Teaches You

### Module 1 — Subdomain Enumeration (`subdomain.py`)
- **DNS resolution** using `dnspython` — how domains map to IPs
- **Passive OSINT** via crt.sh API — certificate transparency logs
- **Active brute-forcing** — trying common subdomain names via DNS
- **Threading** with `concurrent.futures` for speed

### Module 2 — Port Scanning (`portscan.py`)
- **Raw TCP socket scanning** — how `connect_ex()` detects open ports
- **Banner grabbing** — reading what services announce on connection
- **nmap integration** via `python-nmap` for `-sV` version detection
- **Semaphore/threading** patterns for concurrent scanning

### Module 3 — Directory Discovery (`dirscan.py`)
- **HTTP status codes** — 200 (found), 403 (forbidden), 301 (redirect)
- **Async HTTP** with `httpx` + `asyncio` for high-speed scanning
- **Extension fuzzing** — trying .php, .txt, .bak on each word
- **Semaphore limiting** to avoid overwhelming the target

---

## 📚 Upgrade Your Wordlists (Highly Recommended)

Install SecLists for much better coverage:
```bash
sudo apt install seclists
# Or: git clone https://github.com/danielmiessler/SecLists
```

Then use:
- Subdomains: `/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt`
- Directories: `/usr/share/seclists/Discovery/Web-Content/common.txt`
- Big dirs: `/usr/share/seclists/Discovery/Web-Content/big.txt`

---

## 📊 Output

Results are saved to `results/` directory:
- `<target>_<timestamp>.json` — Full machine-readable results
- `<target>_<timestamp>.txt` — Human-readable summary report

---

## ⚖️ Legal Notice

This tool is for **educational and authorized penetration testing only**.  
Unauthorized scanning is illegal under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.

**Safe practice environments:**
- [TryHackMe](https://tryhackme.com)
- [HackTheBox](https://hackthebox.com)
- Your own VMs/lab network
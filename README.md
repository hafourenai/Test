# 🕵️ Stealth Vulnerability Scanner v2.0

**Production-ready vulnerability scanner with dual-engine architecture (Python + Go) featuring proxy rotation and Tor integration for stealth operations.**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](https://www.python.org/)
[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8)](https://golang.org/)
[![License](https://img.shields.io/badge/License-Educational-green)](LICENSE)

## 🎯 Features

### Core Capabilities
- ⚡ **High-Performance Scanning**: Go-based port scanner with concurrent threading
- 🔍 **Service Detection**: Banner grabbing and version fingerprinting
- 🌐 **HTTP Analysis**: Security headers check, HTTP methods detection
- 🗄️ **CVE Matching**: Automatic vulnerability identification against CVE database
- 🔌 **Plugin System**: Extensible security check plugins
- 💾 **Database Persistence**: SQLite storage for scan history
- 🌐 **REST API**: Integration-ready API server

### 🔒 Stealth Features
- 🔄 **Proxy Rotation**: Automatic rotation through multiple proxies
- 🧅 **Tor Integration**: Route traffic through Tor network
- 🎭 **Anti-Detection**: User-Agent randomization, adaptive rate limiting
- 📡 **IP Verification**: Confirm exit IP before/after scans
- ⏱️ **Request Jitter**: Random delays to avoid pattern detection
- 🛡️ **WAF Evasion**: Stealth techniques to bypass web application firewalls

## 📋 Requirements

### System Requirements
- **Python**: 3.8 or higher
- **Go**: 1.21 or higher
- **OS**: Windows, Linux, or macOS
- **Tor** (optional): For Tor network integration

### Python Dependencies
```
requests>=2.31.0
stem>=1.8.2
PySocks>=1.7.1
pyyaml>=6.0.1
tqdm>=4.66.1
colorama>=0.4.6
```

### Go Dependencies
```
github.com/gorilla/mux v1.8.1
github.com/mattn/go-sqlite3 v1.14.18
golang.org/x/net v0.19.0
```

## 🚀 Installation

### 1. Clone Repository
```bash
cd d:\Vuln
```

### 2. Setup Go Scanner
```bash
cd go
go mod tidy
go build -o scanner.exe main.go
cd ..
```

### 3. Setup Python Environment
```bash
cd python
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install -r ../requirements.txt
```

### 4. (Optional) Install and Configure Tor
**Windows:**
- Download Tor Browser from https://www.torproject.org/
- Or install Tor as a service

**Linux:**
```bash
sudo apt-get install tor
sudo systemctl start tor
sudo systemctl enable tor
```

**Verify Tor is running:**
```bash
# Should show Tor listening on port 9050
netstat -an | findstr 9050
```

### 5. Configure Proxies (Optional)
Edit `proxies.txt` with your proxy list:
```
# HTTP proxies
http://proxy1.example.com:8080
http://user:pass@proxy2.example.com:3128

# SOCKS5 proxies
socks5://proxy3.example.com:1080

# Plain format (defaults to HTTP)
user:pass@198.51.100.1:8080
```

## 📖 Usage

### Basic Scan
```bash
cd python
python main.py scanme.nmap.org --accept-disclaimer
```

### Stealth Scan with Proxies
```bash
python main.py target.com --use-proxies --accept-disclaimer
```

### Tor Network Scan
```bash
python main.py target.com --use-tor --accept-disclaimer
```

### Full Stealth Mode (Tor + Proxies)
```bash
python main.py target.com --use-tor --use-proxies --accept-disclaimer
```

### Test Proxy Configuration
```bash
python main.py dummy --test-proxies --use-proxies
```

### Custom Port Range
```bash
python main.py target.com -s 1 -e 10000 --threads 200 --accept-disclaimer
```

### Save Results to File
```bash
python main.py target.com -o ../output/scan_results.json --accept-disclaimer
```

### Validate Proxies Before Scan
```bash
python main.py target.com --use-proxies --validate-proxies --accept-disclaimer
```

## 🎛️ Command-Line Options

### Target Options
- `target` - Target IP address or domain (required)
- `-s, --start-port` - Start port (default: 1)
- `-e, --end-port` - End port (default: 1000)
- `-t, --timeout` - Connection timeout in seconds (default: 2)
- `-T, --threads` - Number of concurrent threads (default: 100)

### Stealth Options
- `--use-proxies` - Enable proxy rotation from proxies.txt
- `--use-tor` - Use Tor network (requires Tor installed)
- `--proxies-file PATH` - Custom proxy file path
- `--test-proxies` - Test proxy configuration and exit
- `--validate-proxies` - Validate all proxies before scanning
- `--rotate-interval N` - Rotate proxy every N requests (default: 10)

### Scanner Options
- `-o, --output FILE` - Save results to JSON file
- `--no-cve` - Skip CVE matching
- `--no-plugins` - Skip plugin execution
- `-v, --verbose` - Verbose output
- `--accept-disclaimer` - Accept legal disclaimer

## 📊 Output Format

### Console Output
```
╔═══════════════════════════════════════════════════╗
║   VULNERABILITY SCANNER v2.0 - STEALTH EDITION    ║
╚═══════════════════════════════════════════════════╝

🎯 Target: example.com
⏰ Timestamp: 2026-01-17T10:00:00Z

🔒 Stealth Mode:
   🧅 Tor: ENABLED
   🔄 Proxies: 10 loaded
   📡 Exit IP: 198.51.100.50

📈 Statistics:
   Open Ports: 5
   Services Detected: 5
   Vulnerabilities Found: 2
   Plugin Findings: 3
```

### JSON Output
```json
{
  "metadata": {
    "scanner_version": "2.0-stealth",
    "timestamp": "2026-01-17T10:00:00Z",
    "target": "example.com",
    "stealth_mode": {
      "proxies_enabled": true,
      "tor_enabled": true,
      "proxy_count": 10,
      "exit_ip": "198.51.100.50"
    }
  },
  "scan_results": { ... },
  "vulnerabilities": [ ... ],
  "plugin_findings": [ ... ]
}
```

## 🔌 Plugin System

### Available Plugins
1. **Security Headers Checker** - Detects missing HTTP security headers
2. **Insecure HTTP Methods** - Identifies dangerous HTTP methods (TRACE, PUT, DELETE)

### Creating Custom Plugins
Create a new file in `python/plugins/`:

```python
from plugins.base_plugin import BasePlugin

class MyPlugin(BasePlugin):
    def __init__(self):
        super().__init__()
        self.name = "My Custom Plugin"
        self.description = "Custom security check"
        self.severity = "Medium"
    
    def analyze(self, scan_results):
        findings = []
        # Your analysis logic here
        return findings
```

## 🗄️ Database

Scan results are automatically saved to SQLite database at `go/vulnerabilities.db`.

### Query Scan History
```bash
sqlite3 go/vulnerabilities.db "SELECT * FROM scans ORDER BY timestamp DESC LIMIT 10;"
```

## 🌐 REST API Mode

### Start API Server
```bash
cd go
go run main.go -api -apiport 8000
```

### API Endpoints
- `GET /api/health` - Health check
- `POST /api/scan` - Trigger new scan
- `GET /api/scans` - List recent scans
- `GET /api/scans/{id}` - Get scan details

### Example API Request
```bash
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "start_port": 1,
    "end_port": 1000,
    "timeout": 2,
    "threads": 100
  }'
```

## ⚖️ Legal Disclaimer

**IMPORTANT: READ BEFORE USE**

- ✅ Only scan systems you **own** or have **written permission** to test
- ❌ Unauthorized scanning may be **illegal** in your jurisdiction
- 🔒 Using proxies/Tor does **NOT** make illegal activity legal
- 📝 Proxy/Tor usage may be **monitored** or **restricted**
- ⚠️ User assumes **all responsibility** for scanner usage
- 🎓 This tool is for **security research and education** ONLY

### Privacy Notice
- Proxies may **log your traffic**
- Use **trusted proxy providers** only
- Tor provides **anonymity** but not **legal immunity**
- Your ISP may **detect Tor usage**

## 📚 Documentation

- [STEALTH_GUIDE.md](STEALTH_GUIDE.md) - Detailed stealth features guide
- [config/config.yaml](config/config.yaml) - Configuration reference
- [config/cve_feed.json](config/cve_feed.json) - CVE database

## 🏗️ Architecture

```
┌─────────────────────────────────────────┐
│   CLI Interface (Python)                │
│   - Stealth mode flags                   │
│   - Proxy/Tor configuration              │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│   Stealth Orchestrator (Python)         │
│   - ProxyManager integration             │
│   - Tor control                          │
│   - IP rotation logic                    │
└──────────────┬──────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────┐
│   Go Scan Engine (Enhanced)             │
│   - Proxy dialer (SOCKS5/HTTP)          │
│   - Port scanning                        │
│   - Service detection                    │
│   - HTTP analysis                        │
└─────────────────────────────────────────┘
```

## 🤝 Contributing

This is an educational project. Contributions for legitimate security research purposes are welcome.

## 📄 License

Educational and Research Use Only

## 🙏 Acknowledgments

- NIST National Vulnerability Database (NVD)
- MITRE CVE Database
- The Tor Project
- Go and Python communities

---

**⚠️ Remember: With great power comes great responsibility. Use ethically!**

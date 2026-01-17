# 🕵️ Stealth Vulnerability Scanner v2.0

**Professional vulnerability scanner with dual-engine architecture (Python + Go) featuring pure-Go self-contained binaries for maximum portability and stealth.**

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
- 💾 **Pure Go Database**: SQLite storage using `modernc.org/sqlite` (no CGO required)
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
- **Go**: 1.21 or higher (Recommended: 1.25+ for pure Go stability)
- **Python**: 3.8 or higher
- **OS**: Linux (Kali/Ubuntu), Windows, or macOS
- **Tor** (optional): For Tor network integration

### Core Dependencies (Automatic)
- **Go**: `modernc.org/sqlite`, `github.com/gorilla/mux`, `golang.org/x/net`
- **Python**: `requests`, `stem`, `PySocks`, `pyyaml`

## 🚀 Installation

### 1. Build the Go Scan Engine
The engine is now a **self-contained binary**. You don't need SQLite installed on your system to build or run it.

```bash
cd go
# For Linux (AMD64)
export CGO_ENABLED=0
go build -ldflags "-s -w" -o scanner main.go

# For Windows (AMD64)
set CGO_ENABLED=0
go build -ldflags "-s -w" -o scanner.exe main.go
```

### 2. Setup Python Orchestrator
```bash
cd python
python -m venv venv

# Windows
venv\Scripts\activate
# Linux
source venv/bin/activate

pip install -r ../requirements.txt
```

## 📖 Usage

### Specifying the Target
Target can be an **IP address** (e.g., `192.168.1.1`) or a **Domain** (e.g., `example.com`).
> [!IMPORTANT]
> Do **NOT** include `http://` or `https://` in the CLI target argument.

### Basic Scan (CLI)
```bash
# Using the Go engine directly (Fastest)
./go/scanner -target scanme.nmap.org -start 1 -end 1000

# Using the Python Orchestrator (Recommended for Stealth)
python python/main.py scanme.nmap.org --use-tor --accept-disclaimer
```

### Advanced Stealth Options
- `--use-proxies`: Enable proxy rotation from `proxies.txt`
- `--use-tor`: Route all traffic through the Tor network
- `--threads 200`: Increase scanning speed
- `-o results.json`: Save detailed findings to JSON

### REST API Mode
Start the scanner as a background service:
```bash
./go/scanner -api -apiport 8000
```
Then interact via REST:
`POST /api/scan` with `{"target": "example.com"}`

## 🗄️ Database Access
Scan history is stored in `go/vulnerabilities.db`. Since it's a standard SQLite file, you can query it:
```bash
sqlite3 go/vulnerabilities.db "SELECT * FROM scans;"
```

## ⚖️ Legal Disclaimer
**Educational Use Only.** Unauthorized scanning is illegal. You are responsible for your actions. See full disclaimer in `main.py` or `LICENSE`.

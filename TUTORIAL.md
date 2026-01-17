# 📖 Stealth Vulnerability Scanner - Tutorial

Welcome to the **Stealth Vulnerability Scanner v2.0**. This guide will help you get started with the tool, from basic scanning to advanced stealth operations.

## 🛠️ Step 1: Environment Setup

Ensure you have **Python 3.8+** and **Go 1.21+** installed.

### 1.1 Python Setup
1. Open a terminal in the project root.
2. Initialize virtual environment:
   ```bash
   cd python
   python -m venv venv
   source venv/bin/activate  # Kali Linux / Linux / Mac
   # or source venv/Scripts/activate # Windows
   pip install -r ../requirements.txt
   ```

### 1.2 Go Scanner Setup
1. Compile the port scanning engine:
   ```bash
   cd go
   go mod tidy
   go build -o scanner main.go  # On Windows, this creates scanner.exe automatically
   chmod +x scanner           # Required on Kali Linux / Linux
   ```

> [!TIP]
> **Kali Linux Safety**: Tool ini sangat aman digunakan di Kali Linux karena dirancang khusus untuk audit keamanan. Fitur stealth (Tor & Proxy) membantu melindungi IP asli Anda dari deteksi atau pemblokiran oleh target.

---

## 🔍 Step 2: Basic Usage

To run a standard scan on a target (e.g., `scanme.nmap.org`):

```bash
python python/main.py scanme.nmap.org --accept-disclaimer
```

**What this does:**
- Scans ports 1-1000.
- Detects running services and versions.
- Matches findings against a local CVE database.
- Runs security header checks.

---

## 🎭 Step 3: Stealth Operations

To hide your tracks using proxy rotation or Tor:

### 3.1 Using Proxies
1. Add your proxies to `proxies.txt` in the root directory.
2. Run with `--use-proxies`:
   ```bash
   python python/main.py target.com --use-proxies --accept-disclaimer
   ```

### 3.2 Using Tor
1. Ensure Tor is running on your system (port 9050).
2. Run with `--use-tor`:
   ```bash
   python python/main.py target.com --use-tor --accept-disclaimer
   ```

### 3.3 Full Stealth Mode
```bash
python python/main.py target.com --use-tor --use-proxies --rotate-interval 5 --accept-disclaimer
```

---

## 📊 Step 4: Vulnerability Database (NVD)

The scanner uses a local CVE feed for matching. To keep it updated with the latest data from NIST:

1. Add your NVD API Key to your `.env` file:
   ```
   NVD_API_KEY=your-api-key-here
   ```
2. Run the update script:
   ```bash
   python python/update_cve_database.py
   ```

---

## 🌐 Step 5: API Mode

You can also run the scanner as a REST API server (Go engine):

1. Start the server:
   ```bash
   cd go
   ./scanner.exe -api -apiport 8000
   ```
2. Send a scan request:
   ```bash
   curl -X POST http://localhost:8000/api/scan -H "Content-Type: application/json" -d '{"target": "example.com"}'
   ```

---

## 🚩 Tips for Better Results
- **Verbosity**: Use `-v` to see raw JSON output.
- **Port Ranges**: Use `-s 1 -e 65535` for a full scan.
- **Save Results**: Use `-o output.json` to export findings.

> [!WARNING]
> Only scan targets you have explicit permission to test. Unauthorized scanning is illegal.

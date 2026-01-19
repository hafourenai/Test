# Love U N - Vulnerability Scanner

A professional-grade, anonymous vulnerability scanner with Tor integration, proxy rotation, and real-time NVD intelligence.

## Installation

### Prerequisites
- Python 3.9+
- Go 1.18+
- Tor (installed and running)

### Steps
1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd Vuln
   ```

2. **Install Python dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Build the Go scanner:**
   ```bash
   cd go
   go build -o scanner.exe main.go
   cd ..
   ```

4. **Configure Environment:**
   Create a `.env` file in the root directory:
   ```env
   NVD_API_KEY=your_api_key_here (optional but recommended)
   ```

## Usage

### Verify Tor Connection
Ensure Tor is running at `127.0.0.1:9050`, then run:
```bash
python python/test_tor.py
```

### Run a Stealth Scan
Scan a target anonymously through the Tor network:
```bash
python python/main.py <target> --use-tor --accept-disclaimer
```

### Run with Proxy Rotation
```bash
python python/main.py <target> --use-proxies --proxies-file proxies.txt --accept-disclaimer
```

### Cleanup Project
Remove Python cache and temporary files:
```bash
python clean.py
```

### Options
- `--target <target>`: IP or domain to scan
- `--use-tor`: Route all traffic through Tor
- `--use-proxies`: Use proxy rotation from a file
- `--no-cve`: Disable NVD vulnerability correlation
- `--output <dir>`: Directory for reports (default: ./reports)

## Disclaimer
This tool is for educational and ethical research purposes only. Unauthorized scanning is illegal.

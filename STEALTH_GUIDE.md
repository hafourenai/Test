# 🕵️ Stealth Features Guide

Complete guide to using proxy rotation and Tor integration for stealth vulnerability scanning.

## 📋 Table of Contents

1. [Overview](#overview)
2. [Proxy Rotation](#proxy-rotation)
3. [Tor Integration](#tor-integration)
4. [Anti-Detection Mechanisms](#anti-detection-mechanisms)
5. [IP Verification](#ip-verification)
6. [Troubleshooting](#troubleshooting)
7. [Best Practices](#best-practices)

---

## 🎯 Overview

The Stealth Vulnerability Scanner includes advanced features to avoid detection and blocking during security assessments:

- **Proxy Rotation**: Automatically rotate through multiple proxies
- **Tor Integration**: Route traffic through the Tor anonymity network
- **Rate Limiting**: Adaptive delays to mimic human behavior
- **User-Agent Randomization**: Avoid fingerprinting
- **IP Verification**: Confirm your exit IP address

---

## 🔄 Proxy Rotation

### Setup Proxy List

1. **Create/Edit `proxies.txt`** in the root directory:

```text
# HTTP proxies
http://proxy1.example.com:8080
http://user:pass@proxy2.example.com:3128

# SOCKS5 proxies
socks5://proxy3.example.com:1080

# Plain format (defaults to HTTP)
198.51.100.1:8080
user:pass@203.0.113.10:3128
```

### Supported Proxy Formats

| Format | Example |
|--------|---------|
| HTTP | `http://proxy.com:8080` |
| HTTP with auth | `http://user:pass@proxy.com:8080` |
| SOCKS5 | `socks5://proxy.com:1080` |
| Plain (HTTP) | `proxy.com:8080` |
| Plain with auth | `user:pass@proxy.com:8080` |

### Using Proxies

**Basic proxy scan:**
```bash
python main.py target.com --use-proxies --accept-disclaimer
```

**Custom proxy file:**
```bash
python main.py target.com --use-proxies --proxies-file /path/to/proxies.txt --accept-disclaimer
```

**Validate proxies before scan:**
```bash
python main.py target.com --use-proxies --validate-proxies --accept-disclaimer
```

**Test proxy configuration:**
```bash
python main.py dummy --test-proxies --use-proxies
```

### Proxy Rotation Behavior

- **Automatic Rotation**: Proxies rotate every 10 requests by default
- **Sequential Selection**: Proxies are used in shuffled order
- **Fallback**: If a proxy fails, the next one is tried automatically
- **Retry Logic**: 3 attempts per request with different proxies

### Custom Rotation Interval

```bash
python main.py target.com --use-proxies --rotate-interval 5 --accept-disclaimer
```

---

## 🧅 Tor Integration

### Installing Tor

**Windows:**
1. Download Tor Browser from https://www.torproject.org/
2. Or install Tor Expert Bundle for service mode

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get update
sudo apt-get install tor
sudo systemctl start tor
sudo systemctl enable tor
```

**macOS:**
```bash
brew install tor
brew services start tor
```

### Verify Tor is Running

```bash
# Check if Tor is listening on port 9050
netstat -an | grep 9050

# Or check Tor status (Linux)
sudo systemctl status tor
```

### Using Tor

**Basic Tor scan:**
```bash
python main.py target.com --use-tor --accept-disclaimer
```

**Test Tor connection:**
```bash
python main.py dummy --test-proxies --use-tor
```

**Expected output:**
```
🧪 Testing Proxy Setup...
   📡 Your real IP:
      203.0.113.50
   🔄 IP through proxy/Tor:
      198.51.100.75
   ✅ Proxy/Tor is working correctly!
```

### Tor Configuration

Default Tor settings:
- **SOCKS5 Port**: 9050
- **Control Port**: 9051 (for circuit renewal)

### Tor Circuit Renewal

The scanner automatically renews Tor circuits every 10 requests using the `stem` library:

```python
# Automatic renewal in code
if self.request_count % 10 == 0:
    proxy_manager.renew_tor_identity()
```

### Combining Tor with Proxies

**Use Tor as primary, proxies as fallback:**
```bash
python main.py target.com --use-tor --use-proxies --accept-disclaimer
```

**Behavior:**
1. Try Tor first
2. If Tor fails, use proxy rotation
3. If all fail, report error

---

## 🎭 Anti-Detection Mechanisms

### 1. User-Agent Randomization

The scanner randomly selects from 5+ realistic User-Agents:

```python
user_agents = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36...',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)...',
    'Mozilla/5.0 (X11; Linux x86_64)...',
    # ... more
]
```

### 2. Adaptive Rate Limiting

**Base delay**: 1-2 seconds between requests  
**Random jitter**: 0-500ms additional delay

```python
# Configured in config.yaml
rate_limiting:
  min_request_interval: 1.0
  max_jitter: 0.5
```

### 3. Request Patterns

- **Shuffled test methods**: Randomize order of security checks
- **Random delays between phases**: Avoid predictable patterns
- **Proxy rotation**: Change IP regularly

### 4. Go Scanner Stealth

The Go scanner also supports proxies via environment variables:

```bash
# Set proxy for Go scanner
export HTTP_PROXY=http://proxy.com:8080
export HTTPS_PROXY=http://proxy.com:8080
export SOCKS5_PROXY=socks5://proxy.com:1080
export USE_TOR=1

# Then run scan
python main.py target.com --use-tor --accept-disclaimer
```

---

## 📡 IP Verification

### Why Verify IP?

- Confirm proxies/Tor are working
- Detect proxy failures
- Ensure anonymity before scanning

### Automatic IP Verification

The scanner automatically shows your IP before scanning:

```
🧪 Testing Proxy Setup...
   📡 Your real IP:
      203.0.113.50
   🔄 IP through proxy/Tor:
      198.51.100.75
   ✅ Proxy/Tor is working correctly!
```

### Manual IP Check

```bash
python main.py dummy --test-proxies --use-tor
```

### IP Verification Services

The scanner uses `httpbin.org/ip` for IP verification:

```python
response = requests.get('http://httpbin.org/ip', proxies=proxy)
ip = response.json().get('origin')
```

---

## 🔧 Troubleshooting

### Proxy Issues

**Problem: "Proxy test failed"**

**Solutions:**
1. Check proxy format in `proxies.txt`
2. Verify proxy is online and accessible
3. Test proxy manually:
   ```bash
   curl -x http://proxy.com:8080 http://httpbin.org/ip
   ```
4. Check authentication credentials

**Problem: "No proxies loaded"**

**Solutions:**
1. Ensure `proxies.txt` exists in root directory
2. Check file has valid proxy entries
3. Remove blank lines and comments

### Tor Issues

**Problem: "Could not start Tor automatically"**

**Solutions:**
1. Install Tor: `sudo apt-get install tor`
2. Start Tor service: `sudo systemctl start tor`
3. Check Tor is listening: `netstat -an | grep 9050`

**Problem: "Tor identity renewal failed"**

**Solutions:**
1. Install stem library: `pip install stem`
2. Check Tor control port (9051) is accessible
3. Verify Tor configuration allows control connections

**Problem: "IP not changed"**

**Solutions:**
1. Verify Tor is actually running
2. Check no other proxy settings override Tor
3. Test Tor Browser to confirm Tor works
4. Check firewall isn't blocking Tor

### Go Scanner Issues

**Problem: "Go build failed"**

**Solutions:**
1. Install Go: https://golang.org/dl/
2. Run `go mod tidy` in `go/` directory
3. Check Go version: `go version` (need 1.21+)

**Problem: "Scanner timeout"**

**Solutions:**
1. Increase timeout: `-t 5`
2. Reduce thread count: `-T 50`
3. Check target is reachable
4. Verify proxy isn't too slow

---

## 🛡️ Best Practices

### 1. Proxy Selection

✅ **DO:**
- Use reputable proxy providers
- Rotate proxies frequently
- Validate proxies before important scans
- Use SOCKS5 for better compatibility

❌ **DON'T:**
- Use free public proxies for sensitive scans
- Reuse same proxy for extended periods
- Trust proxies that log traffic
- Use proxies from unknown sources

### 2. Tor Usage

✅ **DO:**
- Verify Tor is working before scan
- Use Tor for maximum anonymity
- Combine with proxies for redundancy
- Renew circuits regularly

❌ **DON'T:**
- Assume Tor makes illegal activity legal
- Forget that Tor can be detected
- Use Tor without understanding risks
- Rely solely on Tor for critical operations

### 3. Rate Limiting

✅ **DO:**
- Use conservative delays (2-3s)
- Add random jitter
- Respect target's resources
- Monitor for blocking

❌ **DON'T:**
- Scan too aggressively
- Use predictable timing patterns
- Ignore rate limit warnings
- Overwhelm target systems

### 4. Operational Security

✅ **DO:**
- Test setup before real scans
- Verify IP changes
- Keep logs secure
- Use VPN + Tor for critical work

❌ **DON'T:**
- Scan without permission
- Ignore legal implications
- Trust proxies blindly
- Leave traces

### 5. Ethical Guidelines

✅ **DO:**
- Get written permission
- Follow responsible disclosure
- Document your testing
- Respect scope boundaries

❌ **DON'T:**
- Scan unauthorized targets
- Exploit found vulnerabilities
- Share sensitive findings publicly
- Exceed authorized scope

---

## 📊 Stealth Mode Comparison

| Feature | No Stealth | Proxies Only | Tor Only | Tor + Proxies |
|---------|-----------|--------------|----------|---------------|
| IP Anonymity | ❌ | ✅ | ✅✅ | ✅✅✅ |
| Detection Resistance | ❌ | ✅ | ✅✅ | ✅✅✅ |
| Speed | ✅✅✅ | ✅✅ | ✅ | ✅ |
| Reliability | ✅✅✅ | ✅✅ | ✅✅ | ✅✅✅ |
| Setup Complexity | ✅✅✅ | ✅✅ | ✅✅ | ✅ |

---

## 🎓 Advanced Usage

### Custom Proxy Rotation Strategy

Edit `python/proxy_manager.py`:

```python
# Change rotation strategy
proxy = proxy_manager.get_current_proxy(strategy='random')  # Random selection
proxy = proxy_manager.get_current_proxy(strategy='rotate')  # Sequential
proxy = proxy_manager.get_current_proxy(strategy='tor-fallback')  # Tor first
```

### Adjust Rate Limiting

Edit `config/config.yaml`:

```yaml
rate_limiting:
  min_request_interval: 2.0  # 2 seconds minimum
  max_jitter: 1.0  # Up to 1 second jitter
```

### Custom User-Agents

Edit `python/proxy_manager.py`:

```python
user_agents = [
    'Your-Custom-User-Agent-1',
    'Your-Custom-User-Agent-2',
    # Add more...
]
```

---

## 📞 Support

For issues or questions:
1. Check this guide
2. Review [README.md](README.md)
3. Check configuration files
4. Test components individually

---

**🔒 Remember: Stealth features are for authorized security testing only!**

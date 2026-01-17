// go/main.go
package main

import (
	"crypto/tls"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"golang.org/x/net/proxy"
	_ "modernc.org/sqlite"
)

// ScanResult represents the complete scan output
type ScanResult struct {
	Target    string         `json:"target"`
	OpenPorts []int          `json:"open_ports"`
	Services  []ServiceInfo  `json:"services"`
	HTTPInfo  []HTTPScanInfo `json:"http_info,omitempty"`
	Timestamp string         `json:"timestamp"`
}

// ServiceInfo contains detected service information
type ServiceInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Version string `json:"version"`
	Banner  string `json:"banner,omitempty"`
}

// HTTPScanInfo contains HTTP-specific scan results
type HTTPScanInfo struct {
	URL            string            `json:"url"`
	StatusCode     int               `json:"status_code"`
	Headers        map[string]string `json:"headers"`
	MissingHeaders []string          `json:"missing_headers"`
	AllowedMethods []string          `json:"allowed_methods,omitempty"`
}

// ProxyConfig holds proxy configuration
type ProxyConfig struct {
	HTTPProxy    string
	HTTPSProxy   string
	SOCKS5Proxy  string
	UseTor       bool
	TorSOCKSAddr string
}

// Global database connection
var db *sql.DB

func main() {
	// CLI mode flags
	target := flag.String("target", "", "Target IP or domain")
	startPort := flag.Int("start", 1, "Start port")
	endPort := flag.Int("end", 1000, "End port")
	timeout := flag.Int("timeout", 2, "Timeout in seconds")
	threads := flag.Int("threads", 100, "Concurrent threads")
	
	// API mode flags
	apiMode := flag.Bool("api", false, "Run in API mode")
	apiPort := flag.Int("apiport", 8000, "API server port")
	
	// Database flag
	dbPath := flag.String("db", "vulnerabilities.db", "SQLite database path")
	
	flag.Parse()

	// Initialize database
	var err error
	db, err = initDatabase(*dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// API Mode
	if *apiMode {
		log.Printf("Starting API server on port %d...", *apiPort)
		startAPIServer(*apiPort)
		return
	}

	// CLI Mode
	if *target == "" {
		fmt.Println("Error: target is required in CLI mode")
		flag.Usage()
		os.Exit(1)
	}

	result := performScan(*target, *startPort, *endPort, *timeout, *threads)
	
	// Save to database
	if err := saveToDatabase(result); err != nil {
		log.Printf("Warning: Failed to save to database: %v", err)
	}

	// Output JSON
	output, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error encoding JSON: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(output))
}

// getProxyConfig reads proxy settings from environment
func getProxyConfig() *ProxyConfig {
	config := &ProxyConfig{
		HTTPProxy:    os.Getenv("HTTP_PROXY"),
		HTTPSProxy:   os.Getenv("HTTPS_PROXY"),
		SOCKS5Proxy:  os.Getenv("SOCKS5_PROXY"),
		TorSOCKSAddr: "127.0.0.1:9050",
	}

	// Check if Tor should be used
	if os.Getenv("USE_TOR") == "1" || os.Getenv("USE_TOR") == "true" {
		config.UseTor = true
	}

	return config
}

// createProxyDialer creates a dialer with proxy support
func createProxyDialer(config *ProxyConfig, timeout time.Duration) (proxy.Dialer, error) {
	// If Tor is enabled, use SOCKS5
	if config.UseTor || config.SOCKS5Proxy != "" {
		socksAddr := config.TorSOCKSAddr
		if config.SOCKS5Proxy != "" {
			socksAddr = config.SOCKS5Proxy
		}

		// Create SOCKS5 dialer
		dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, &net.Dialer{
			Timeout: timeout,
		})
		if err != nil {
			log.Printf("Failed to create SOCKS5 proxy: %v", err)
			// Fallback to direct connection
			return &net.Dialer{Timeout: timeout}, nil
		}
		return dialer, nil
	}

	// Use standard dialer
	return &net.Dialer{Timeout: timeout}, nil
}

// createHTTPClientWithProxy creates HTTP client with proxy support
func createHTTPClientWithProxy(config *ProxyConfig) *http.Client {
	// Create transport
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // For testing purposes
		},
		DisableKeepAlives: true,
	}

	// Configure proxy
	if config.UseTor || config.SOCKS5Proxy != "" {
		// Use SOCKS5 proxy for Tor
		socksAddr := config.TorSOCKSAddr
		if config.SOCKS5Proxy != "" {
			socksAddr = config.SOCKS5Proxy
		}

		dialer, err := proxy.SOCKS5("tcp", socksAddr, nil, proxy.Direct)
		if err == nil {
			transport.Dial = dialer.Dial
		} else {
			log.Printf("SOCKS5 proxy failed, using direct connection: %v", err)
		}
	} else if config.HTTPProxy != "" {
		// Use HTTP/HTTPS proxy
		proxyURL, err := url.Parse(config.HTTPProxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyURL)
		}
	}

	return &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// performScan executes the scanning logic with proxy support
func performScan(target string, startPort, endPort, timeout, threads int) ScanResult {
	result := ScanResult{
		Target:    target,
		OpenPorts: []int{},
		Services:  []ServiceInfo{},
		HTTPInfo:  []HTTPScanInfo{},
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	// Get proxy configuration
	config := getProxyConfig()

	if config.UseTor {
		log.Printf("🧅 Using Tor network (SOCKS5: %s)", config.TorSOCKSAddr)
	} else if config.HTTPProxy != "" {
		log.Printf("🔄 Using HTTP proxy: %s", config.HTTPProxy)
	} else if config.SOCKS5Proxy != "" {
		log.Printf("🔄 Using SOCKS5 proxy: %s", config.SOCKS5Proxy)
	}

	// Port Scanning
	log.Printf("Scanning ports %d-%d on %s...", startPort, endPort, target)
	openPorts := scanPorts(target, startPort, endPort, timeout, threads, config)
	result.OpenPorts = openPorts
	log.Printf("Found %d open ports", len(openPorts))

	// Service Detection
	for _, port := range openPorts {
		service := detectService(target, port, timeout, config)
		result.Services = append(result.Services, service)

		// HTTP Scanning for web ports
		if port == 80 || port == 443 || port == 8080 || port == 8443 {
			httpInfo := scanHTTP(target, port, config)
			if httpInfo.URL != "" {
				result.HTTPInfo = append(result.HTTPInfo, httpInfo)
			}
		}
	}

	return result
}

// scanPorts performs parallel TCP port scanning with proxy support
func scanPorts(target string, startPort, endPort, timeout, threads int, config *ProxyConfig) []int {
	openPorts := []int{}
	var mu sync.Mutex
	var wg sync.WaitGroup

	semaphore := make(chan struct{}, threads)

	// Create proxy dialer
	proxyDialer, err := createProxyDialer(config, time.Duration(timeout)*time.Second)
	if err != nil {
		log.Printf("Warning: Using direct connection (proxy creation failed)")
	}

	for port := startPort; port <= endPort; port++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			address := fmt.Sprintf("%s:%d", target, p)

			// Use proxy dialer
			conn, err := proxyDialer.Dial("tcp", address)
			if err == nil {
				conn.Close()
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}

	wg.Wait()
	return openPorts
}

// detectService performs banner grabbing and service detection with proxy
func detectService(target string, port, timeout int, config *ProxyConfig) ServiceInfo {
	service := ServiceInfo{
		Port:    port,
		Service: "unknown",
		Version: "unknown",
		Banner:  "",
	}

	address := fmt.Sprintf("%s:%d", target, port)

	// Create proxy dialer
	proxyDialer, err := createProxyDialer(config, time.Duration(timeout)*time.Second)
	if err != nil {
		log.Printf("Service detection fallback to direct connection")
		proxyDialer = &net.Dialer{Timeout: time.Duration(timeout) * time.Second}
	}

	// Connect through proxy
	conn, err := proxyDialer.Dial("tcp", address)
	if err != nil {
		return service
	}
	defer conn.Close()

	// Set deadline for reading
	conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))

	// Banner grabbing
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err == nil && n > 0 {
		service.Banner = strings.TrimSpace(string(buffer[:n]))
		service.Service, service.Version = parseServiceBanner(service.Banner, port)
	} else {
		service.Service = inferServiceFromPort(port)
	}

	return service
}

// scanHTTP performs basic HTTP vulnerability scanning with proxy
func scanHTTP(target string, port int, config *ProxyConfig) HTTPScanInfo {
	info := HTTPScanInfo{
		Headers:        make(map[string]string),
		MissingHeaders: []string{},
	}

	protocol := "http"
	if port == 443 || port == 8443 {
		protocol = "https"
	}

	targetURL := fmt.Sprintf("%s://%s:%d", protocol, target, port)
	info.URL = targetURL

	// Create HTTP client with proxy support
	client := createHTTPClientWithProxy(config)

	resp, err := client.Get(targetURL)
	if err != nil {
		return HTTPScanInfo{}
	}
	defer resp.Body.Close()

	info.StatusCode = resp.StatusCode

	// Collect headers
	for key, values := range resp.Header {
		info.Headers[key] = strings.Join(values, ", ")
	}

	// Check for missing security headers
	securityHeaders := []string{
		"X-Frame-Options",
		"X-Content-Type-Options",
		"Strict-Transport-Security",
		"Content-Security-Policy",
		"X-XSS-Protection",
	}

	for _, header := range securityHeaders {
		if _, exists := resp.Header[header]; !exists {
			info.MissingHeaders = append(info.MissingHeaders, header)
		}
	}

	// Check allowed methods via OPTIONS
	optReq, _ := http.NewRequest("OPTIONS", targetURL, nil)
	optResp, err := client.Do(optReq)
	if err == nil {
		defer optResp.Body.Close()
		if allow := optResp.Header.Get("Allow"); allow != "" {
			info.AllowedMethods = strings.Split(allow, ",")
			for i := range info.AllowedMethods {
				info.AllowedMethods[i] = strings.TrimSpace(info.AllowedMethods[i])
			}
		}
	}

	return info
}

// parseServiceBanner extracts service and version from banner
func parseServiceBanner(banner string, port int) (string, string) {
	lowerBanner := strings.ToLower(banner)

	// HTTP servers
	if strings.Contains(lowerBanner, "http") {
		if strings.Contains(lowerBanner, "nginx") {
			version := extractVersion(banner, "nginx/")
			return "http-nginx", version
		}
		if strings.Contains(lowerBanner, "apache") {
			version := extractVersion(banner, "apache/")
			return "http-apache", version
		}
		return "http", "unknown"
	}

	// SSH
	if strings.Contains(lowerBanner, "ssh") {
		version := extractVersion(banner, "openssh")
		return "ssh", version
	}

	// FTP
	if strings.Contains(lowerBanner, "ftp") {
		return "ftp", extractVersion(banner, "")
	}

	return inferServiceFromPort(port), "unknown"
}

// extractVersion extracts version from banner string
func extractVersion(banner, prefix string) string {
	parts := strings.Fields(banner)
	for _, part := range parts {
		if strings.Contains(strings.ToLower(part), strings.ToLower(prefix)) {
			return strings.TrimPrefix(part, prefix)
		}
	}
	return "unknown"
}

// inferServiceFromPort guesses service based on port number
func inferServiceFromPort(port int) string {
	commonPorts := map[int]string{
		21:    "ftp",
		22:    "ssh",
		23:    "telnet",
		25:    "smtp",
		53:    "dns",
		80:    "http",
		110:   "pop3",
		143:   "imap",
		443:   "https",
		3306:  "mysql",
		5432:  "postgresql",
		6379:  "redis",
		8080:  "http-proxy",
		8443:  "https-alt",
		27017: "mongodb",
	}

	if service, ok := commonPorts[port]; ok {
		return service
	}
	return "unknown"
}

// Database functions
func initDatabase(dbPath string) (*sql.DB, error) {
	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	schema := `
	CREATE TABLE IF NOT EXISTS scans (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		target TEXT NOT NULL,
		timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
		open_ports TEXT,
		services_json TEXT
	);

	CREATE TABLE IF NOT EXISTS services (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER,
		port INTEGER,
		service TEXT,
		version TEXT,
		banner TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id)
	);

	CREATE TABLE IF NOT EXISTS http_findings (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scan_id INTEGER,
		url TEXT,
		status_code INTEGER,
		missing_headers TEXT,
		allowed_methods TEXT,
		FOREIGN KEY(scan_id) REFERENCES scans(id)
	);
	`

	_, err = database.Exec(schema)
	if err != nil {
		return nil, err
	}

	return database, nil
}

func saveToDatabase(result ScanResult) error {
	stmt, err := db.Prepare(`
		INSERT INTO scans (target, timestamp, open_ports, services_json) 
		VALUES (?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	portsJSON, _ := json.Marshal(result.OpenPorts)
	servicesJSON, _ := json.Marshal(result.Services)

	res, err := stmt.Exec(
		result.Target,
		result.Timestamp,
		string(portsJSON),
		string(servicesJSON),
	)
	if err != nil {
		return err
	}

	scanID, err := res.LastInsertId()
	if err != nil {
		return err
	}

	// Insert service details
	serviceStmt, err := db.Prepare(`
		INSERT INTO services (scan_id, port, service, version, banner) 
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer serviceStmt.Close()

	for _, svc := range result.Services {
		_, err = serviceStmt.Exec(scanID, svc.Port, svc.Service, svc.Version, svc.Banner)
		if err != nil {
			log.Printf("Warning: Failed to insert service: %v", err)
		}
	}

	// Insert HTTP findings
	httpStmt, err := db.Prepare(`
		INSERT INTO http_findings (scan_id, url, status_code, missing_headers, allowed_methods) 
		VALUES (?, ?, ?, ?, ?)
	`)
	if err != nil {
		return err
	}
	defer httpStmt.Close()

	for _, httpInfo := range result.HTTPInfo {
		missingJSON, _ := json.Marshal(httpInfo.MissingHeaders)
		methodsJSON, _ := json.Marshal(httpInfo.AllowedMethods)

		_, err = httpStmt.Exec(
			scanID,
			httpInfo.URL,
			httpInfo.StatusCode,
			string(missingJSON),
			string(methodsJSON),
		)
		if err != nil {
			log.Printf("Warning: Failed to insert HTTP finding: %v", err)
		}
	}

	log.Printf("Scan results saved to database (scan_id: %d)", scanID)
	return nil
}

// API Server functions
type ScanRequest struct {
	Target    string `json:"target"`
	StartPort int    `json:"start_port"`
	EndPort   int    `json:"end_port"`
	Timeout   int    `json:"timeout"`
	Threads   int    `json:"threads"`
}

type APIResponse struct {
	Success bool        `json:"success"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func startAPIServer(port int) {
	router := mux.NewRouter()

	router.HandleFunc("/api/scan", handleScan).Methods("POST")
	router.HandleFunc("/api/scans", handleGetScans).Methods("GET")
	router.HandleFunc("/api/scans/{id}", handleGetScanByID).Methods("GET")
	router.HandleFunc("/api/health", handleHealth).Methods("GET")

	router.Use(corsMiddleware)

	addr := fmt.Sprintf(":%d", port)
	log.Printf("API server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, router))
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	response := APIResponse{
		Success: true,
		Message: "Scanner API is running",
		Data: map[string]string{
			"version": "2.0-stealth",
			"status":  "healthy",
		},
	}
	sendJSON(w, http.StatusOK, response)
}

func handleScan(w http.ResponseWriter, r *http.Request) {
	var req ScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		response := APIResponse{
			Success: false,
			Message: "Invalid request body",
		}
		sendJSON(w, http.StatusBadRequest, response)
		return
	}

	// Set defaults
	if req.StartPort == 0 {
		req.StartPort = 1
	}
	if req.EndPort == 0 {
		req.EndPort = 1000
	}
	if req.Timeout == 0 {
		req.Timeout = 2
	}
	if req.Threads == 0 {
		req.Threads = 100
	}

	if req.Target == "" {
		response := APIResponse{
			Success: false,
			Message: "Target is required",
		}
		sendJSON(w, http.StatusBadRequest, response)
		return
	}

	log.Printf("API scan request: %s", req.Target)
	result := performScan(req.Target, req.StartPort, req.EndPort, req.Timeout, req.Threads)

	if err := saveToDatabase(result); err != nil {
		log.Printf("Warning: Failed to save scan: %v", err)
	}

	response := APIResponse{
		Success: true,
		Message: "Scan completed successfully",
		Data:    result,
	}
	sendJSON(w, http.StatusOK, response)
}

func handleGetScans(w http.ResponseWriter, r *http.Request) {
	rows, err := db.Query(`
		SELECT id, target, timestamp, open_ports 
		FROM scans 
		ORDER BY timestamp DESC 
		LIMIT 50
	`)
	if err != nil {
		response := APIResponse{
			Success: false,
			Message: "Failed to retrieve scans",
		}
		sendJSON(w, http.StatusInternalServerError, response)
		return
	}
	defer rows.Close()

	scans := []map[string]interface{}{}
	for rows.Next() {
		var id int
		var target, timestamp, openPortsJSON string
		if err := rows.Scan(&id, &target, &timestamp, &openPortsJSON); err != nil {
			continue
		}

		var openPorts []int
		json.Unmarshal([]byte(openPortsJSON), &openPorts)

		scans = append(scans, map[string]interface{}{
			"id":         id,
			"target":     target,
			"timestamp":  timestamp,
			"open_ports": openPorts,
		})
	}

	response := APIResponse{
		Success: true,
		Message: "Scans retrieved successfully",
		Data:    scans,
	}
	sendJSON(w, http.StatusOK, response)
}

func handleGetScanByID(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	scanID := vars["id"]

	var target, timestamp, servicesJSON string
	err := db.QueryRow(`
		SELECT target, timestamp, services_json 
		FROM scans 
		WHERE id = ?
	`, scanID).Scan(&target, &timestamp, &servicesJSON)

	if err != nil {
		response := APIResponse{
			Success: false,
			Message: "Scan not found",
		}
		sendJSON(w, http.StatusNotFound, response)
		return
	}

	var services []ServiceInfo
	json.Unmarshal([]byte(servicesJSON), &services)

	scanData := map[string]interface{}{
		"target":    target,
		"timestamp": timestamp,
		"services":  services,
	}

	response := APIResponse{
		Success: true,
		Message: "Scan retrieved successfully",
		Data:    scanData,
	}
	sendJSON(w, http.StatusOK, response)
}

func sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

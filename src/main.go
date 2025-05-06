package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"compress/gzip" // <-- ADD THIS LINE if it's missing
	"github.com/andybalholm/brotli"
	"github.com/vishvananda/netlink"
)

const (
	SharedSecret       = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" // Secret between client & server
	Version            = "2.2"                              // Version of the script
	IPv6Prefix         = "2a01:e5c0:2d74"                   // Your /48 prefix
	IPv6Subnet         = "5000"                             // Using subnet 1000 within your /48
	Interface          = "ens3"                             // Detected interface from your system
	ListenPort         = 80                                 // Proxy server port
	ListenHost         = "0.0.0.0"                          // Listen on all interfaces
	RequestTimeout     = 30 * time.Second                   // Request timeout in seconds
	Debug              = false                              // Enable debug output
	DesiredPoolSize    = 1000                                // Target number of IPs in the pool (Reduced for testing)
	PoolManageInterval = 5 * time.Second                    // Check/add less frequently (every 5 seconds)
	PoolAddBatchSize   = 15                                 // Try to add up to 5 IPs per cycle if needed
)

var random *rand.Rand
var requestCount int
var defaultClient *http.Client
var defaultTransport *http.Transport

var (
	ipPool         []string
	poolMutex      sync.Mutex
	currentIPIndex int
)
var skipHeaders = map[string]bool{
	"transfer-encoding": true,
	"content-encoding":  true,
	"content-length":    true,
	"connection":        true,
	"keep-alive":        true,
	"server":            true,
}

func minInt(x, y int) int {
	if x < y {
		return x
	}
	return y
}

func randomIPv6() string {
	hostPart1 := rand.Uint32()
	hostPart2 := rand.Uint32()

	return fmt.Sprintf("%s:%s:%04x:%04x:%04x:%04x",
		IPv6Prefix,
		IPv6Subnet,
		(hostPart1>>16)&0xFFFF,
		hostPart1&0xFFFF,
		(hostPart2>>16)&0xFFFF,
		hostPart2&0xFFFF)
}

func checkInterface() bool {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		if _, ok := err.(netlink.LinkNotFoundError); ok {
			fmt.Printf("WARNING: Interface %s not found.\n", Interface)
		} else {
			fmt.Printf("Error checking interface %s: %v\n", Interface, err)
		}
		links, listErr := netlink.LinkList()
		if listErr == nil {
			fmt.Println("Available interfaces:")
			for _, l := range links {
				fmt.Printf("  - %s\n", l.Attrs().Name)
			}
		}
		return false
	}
	if (link.Attrs().Flags & net.FlagUp) == 0 {
		fmt.Printf("WARNING: Interface %s is down.\n", Interface)
	}
	fmt.Printf("Interface %s found and appears up.\n", Interface)
	return true
}

func addIPv6ToInterface(ipv6 string) bool {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		fmt.Printf("addIPv6: Failed to find link %s: %v\n", Interface, err)
		return false
	}

	addr, err := netlink.ParseAddr(ipv6 + "/128")
	if err != nil {
		fmt.Printf("addIPv6: Failed to parse address %s/128: %v\n", ipv6, err)
		return false
	}

	err = netlink.AddrAdd(link, addr)
	if err != nil {
		if err.Error() == "file exists" {
			if Debug {
				fmt.Printf("addIPv6: Address %s already exists on %s (ignored).\n", ipv6, Interface)
			}
			return true
		} else {
			fmt.Printf("addIPv6: Failed to add address %s to %s: %v\n", ipv6, Interface, err)
			return false
		}
	}

	if Debug {
		fmt.Printf("addIPv6: Successfully added %s to %s via netlink.\n", ipv6, Interface)
	}
	return true
}

func removeIPv6FromInterface(ipv6 string) bool {
	link, err := netlink.LinkByName(Interface)
	if err != nil {
		fmt.Printf("removeIPv6: Failed to find link %s: %v\n", Interface, err)
		return false
	}

	addr, err := netlink.ParseAddr(ipv6 + "/128")
	if err != nil {
		fmt.Printf("removeIPv6: Failed to parse address %s/128: %v\n", ipv6, err)
		return false
	}

	err = netlink.AddrDel(link, addr)
	if err != nil {
		fmt.Printf("removeIPv6: error removing address %s from %s: %v\n", ipv6, Interface, err)
		return false
	}

	if Debug {
		fmt.Printf("removeIPv6: Successfully removed %s from %s via netlink.\n", ipv6, Interface)
	}
	return true
}

func ensureURLHasScheme(urlStr string) string {
	if !strings.HasPrefix(urlStr, "http://") && !strings.HasPrefix(urlStr, "https://") {
		return "https://" + urlStr
	}
	return urlStr
}

func logRequest(r *http.Request) {
	requestCount++
	fmt.Printf("\nIncoming request #%d\n", requestCount)
}

func validateAPIToken(apiToken string, userAgent string) bool {
	key := []byte(userAgent)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(SharedSecret))
	expectedHash := hex.EncodeToString(h.Sum(nil))

	return hmac.Equal([]byte(apiToken), []byte(expectedHash))
}

func handleRequest(w http.ResponseWriter, r *http.Request) {
	apiToken := r.Header.Get("API-Token")
	userAgent := r.Header.Get("User-Agent")

	if !validateAPIToken(apiToken, userAgent) {
		http.Error(w, "Unauthorized: i6.shark detected invalid API-Token.", http.StatusUnauthorized)
		return
	}

	logRequest(r)

	if Debug {
		fmt.Printf("Raw query string: %s\n", r.URL.RawQuery)
	}

	targetURL := r.URL.Query().Get("destination")
	if Debug {
		fmt.Printf("Retrieved 'destination' parameter (decoded): %s\n", targetURL)
	}
	headersJSON := r.URL.Query().Get("headers")
	useNormalParam := r.URL.Query().Has("normal")

	if targetURL == "" {
		fmt.Fprintf(w, "i6.shark is working as expected (v%s). IP check skipped.", Version)
		return
	}

	targetURL = ensureURLHasScheme(targetURL)
	parsedURL, err := url.Parse(targetURL)
	if Debug {
		if err != nil {
			fmt.Printf("Error parsing decoded URL '%s': %v\n", targetURL, err)
		} else {
			fmt.Printf("Successfully parsed decoded URL: %s (Host: %s)\n", parsedURL.String(), parsedURL.Host)
		}
	}
	if err != nil || parsedURL.Host == "" {
		fmt.Printf("Error parsing URL or empty hostname: %v\n", err)
		http.Error(w, fmt.Sprintf("Invalid URL: %s.", targetURL), http.StatusBadRequest)
		return
	}
	hostname := parsedURL.Host

	var sourceIP string
	var sourceNetIP net.IP
	useSpecificIP := true

	if useNormalParam {
		sourceIP = "System default (requested)"
		useSpecificIP = false
		fmt.Println("Using system default IP as requested by 'normal' parameter.")
	} else {
		var poolErr error
		sourceIP, poolErr = getNextIPFromPool()
		if poolErr != nil {
			fmt.Printf("Warning: IP Pool empty or error, falling back to system default IP. Error: %v\n", poolErr)
			sourceIP = "System default (fallback)"
			useSpecificIP = false
		} else {
			sourceNetIP = net.ParseIP(sourceIP)
			if sourceNetIP == nil {
				fmt.Printf("ERROR: Failed to parse IP from pool: %s. Falling back.\n", sourceIP)
				sourceIP = "System default (fallback)"
				useSpecificIP = false
			} else {
				fmt.Printf("Using IP from pool: %s\n", sourceIP)
			}
		}
	}

	headers := make(http.Header)
	for name, values := range r.Header {
		if strings.ToLower(name) != "host" {
			headers[name] = values
		}
	}

	// Process custom headers from the JSON parameter
	if headersJSON != "" {
		var customHeaders map[string]string
		err := json.Unmarshal([]byte(headersJSON), &customHeaders)
		if err == nil {
			for name, value := range customHeaders {
				headers.Set(name, value)
			}
			if Debug {
				fmt.Printf("Applied custom headers from JSON parameter: %v\n", customHeaders)
			}
		} else {
			fmt.Println("Warning: Failed to parse 'headers' JSON. Ignoring.")
		}
	}

	var client *http.Client

	if useSpecificIP {
		specificTransport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: sourceNetIP, Port: 0},
				Timeout:   RequestTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   5,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		client = &http.Client{
			Transport: specificTransport,
			Timeout:   RequestTimeout,
		}
		fmt.Printf("Using specific transport/client with LocalAddr: %s\n", sourceIP)
	} else {
		client = defaultClient
		fmt.Printf("Using shared default client (Source IP: %s)\n", sourceIP)
	}

	outRequest, err := http.NewRequest(r.Method, targetURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}

	if r.Method == "POST" || r.Method == "PUT" {
		// We still need to read the incoming body to potentially send it.
		// Note: For very large uploads, this still reads into memory.
		// True streaming requires http.Request.GetBody, which is more complex.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Sprintf("Error reading request body: %v", err), http.StatusInternalServerError)
			return
		}
		outRequest.Body = io.NopCloser(bytes.NewReader(body))
		outRequest.ContentLength = int64(len(body))
	} else {
		outRequest.Body = nil
	}

	outRequest.Header = headers
	fmt.Printf("Connecting to %s using source IP %s (via %s)...\n",
		targetURL, sourceIP,
		func() string {
			if useSpecificIP {
				return "specific dialer"
			} else if useNormalParam {
				return "default (requested)"
			} else {
				return "default (fallback)"
			}
		}())
	resp, err := client.Do(outRequest)

	if err != nil {
		fmt.Printf("ERROR using source IP %s for %s: %v\n", sourceIP, targetURL, err)

		if useSpecificIP {
			fmt.Println("Attempting to get interface addresses via netlink during error...")
			link, linkErr := netlink.LinkByName(Interface)
			if linkErr != nil {
				fmt.Printf("  Error getting link %s: %v\n", Interface, linkErr)
			} else {
				addrs, addrErr := netlink.AddrList(link, netlink.FAMILY_V6)
				if addrErr != nil {
					fmt.Printf("  Error listing addresses for %s: %v\n", Interface, addrErr)
				} else {
					foundInNetlink := false
					fmt.Printf("  Current IPv6 addresses on %s at time of error:\n", Interface)
					for _, addr := range addrs {
						fmt.Printf("    - %s (Flags: %d)\n", addr.IPNet.String(), addr.Flags)
						if addr.IP.Equal(sourceNetIP) {
							foundInNetlink = true
						}
					}
					if !foundInNetlink {
						fmt.Printf("  WARNING: Failing source IP %s was NOT found in netlink AddrList at time of error!\n", sourceIP)
					}
				}
			}

			if opError, ok := err.(*net.OpError); ok {
				if sysErr, ok := opError.Err.(*os.SyscallError); ok && (sysErr.Err.Error() == "invalid argument" || sysErr.Err.Error() == "can't assign requested address" || strings.Contains(sysErr.Err.Error(), "no suitable address found")) {
					fmt.Printf("Network Error likely due to unusable source IP %s on interface %s.\n", sourceIP, Interface)

					poolMutex.Lock()
					for i, ip := range ipPool {
						if ip == sourceIP {
							ipPool = append(ipPool[:i], ipPool[i+1:]...)
							fmt.Printf("Removed bad IP %s from the pool.\n", sourceIP)
							break
						}
					}
					poolMutex.Unlock()

					http.Error(w, fmt.Sprintf("Proxy Network Error using %s: %v", sourceIP, err), http.StatusBadGateway)
					return
				}
			}
		}

		if os.IsTimeout(err) || strings.Contains(err.Error(), "timeout") {
			http.Error(w, fmt.Sprintf("Request timed out connecting to %s using source IP %s.", hostname, sourceIP), http.StatusGatewayTimeout)
		} else if strings.Contains(err.Error(), "connection") {
			http.Error(w, fmt.Sprintf("Connection error to %s using source IP %s: %v.", hostname, sourceIP, err), http.StatusBadGateway)
		} else {
			http.Error(w, fmt.Sprintf("Error proxying request using source IP %s: %v.", sourceIP, err), http.StatusInternalServerError)
		}
		return
	}
	defer resp.Body.Close()

	for name, values := range resp.Header {
		if !skipHeaders[strings.ToLower(name)] {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
	}

	var reader io.Reader = resp.Body
	contentEncoding := resp.Header.Get("Content-Encoding")

	if strings.Contains(contentEncoding, "br") {
		reader = brotli.NewReader(resp.Body)
		w.Header().Del("Content-Encoding")
		w.Header().Del("Content-Length")
		if Debug {
			fmt.Println("Decompressing Brotli response stream")
		}
	} else if strings.Contains(contentEncoding, "gzip") {
		gzipReader, err := gzip.NewReader(resp.Body)
		if err != nil {
			fmt.Printf("ERROR: Failed to create gzip reader: %v. Attempting to stream raw body.\n", err)
		} else {
			reader = gzipReader
			defer gzipReader.Close()
			w.Header().Del("Content-Encoding")
			w.Header().Del("Content-Length")
			if Debug {
				fmt.Println("Decompressing Gzip response stream")
			}
		}
	}

	if Debug {
		fmt.Println("Response headers being sent to client:")
		for name, values := range w.Header() {
			for _, value := range values {
				fmt.Printf("  %s: %s\n", name, value)
			}
		}
	}

	w.WriteHeader(resp.StatusCode)

	copiedBytes, err := io.Copy(w, reader)
	if err != nil {
		// Error copying response body (e.g., client closed connection)
		// Can't send HTTP error anymore as headers/status are already sent.
		fmt.Printf("Error streaming response body to client: %v\n", err)
	} else {
		if Debug {
			fmt.Printf("Successfully streamed %d bytes to client.\n", copiedBytes)
		}
	}
}

func getNextIPFromPool() (string, error) {
	poolMutex.Lock()
	defer poolMutex.Unlock()

	if len(ipPool) == 0 {
		return "", errors.New("IP pool is empty")
	}

	for i := 0; i < len(ipPool); i++ {
		index := currentIPIndex
		currentIPIndex = (currentIPIndex + 1) % len(ipPool)

		if net.ParseIP(ipPool[index]) != nil {
			return ipPool[index], nil
		}

		fmt.Printf("Invalid IP found in pool: %s. Skipping...\n", ipPool[index])
	}

	return "", errors.New("no valid IPs in pool")
}

func manageIPPool() {
	fmt.Println("Starting IP pool manager...")
	ticker := time.NewTicker(PoolManageInterval)
	defer ticker.Stop()

	for range ticker.C {
		poolMutex.Lock()
		currentSize := len(ipPool)
		needToAdd := currentSize < DesiredPoolSize
		batchTarget := minInt(PoolAddBatchSize, DesiredPoolSize-currentSize)
		shouldReplace := currentSize >= DesiredPoolSize
		var ipsToRemove []string

		if shouldReplace {
			numToRemove := 1
			if numToRemove > currentSize {
				numToRemove = currentSize
			}

			ipsToRemove = make([]string, numToRemove)
			copy(ipsToRemove, ipPool[:numToRemove])
			ipPool = ipPool[numToRemove:]
			currentSize -= numToRemove

			if currentIPIndex >= currentSize && currentSize > 0 {
				currentIPIndex = 0
			}
		}
		poolMutex.Unlock()

		if len(ipsToRemove) > 0 {
			var wg sync.WaitGroup
			for _, oldestIP := range ipsToRemove {
				if oldestIP != "" {
					wg.Add(1)
					go func(ip string) {
						defer wg.Done()
						removeIPv6FromInterface(ip)
					}(oldestIP)
				}
			}
			wg.Wait()
		}

		if needToAdd && batchTarget > 0 {
			var wg sync.WaitGroup
			newIPs := make(chan string, batchTarget)

			for i := 0; i < batchTarget; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					newIP := randomIPv6()
					if addIPv6ToInterface(newIP) {
						newIPs <- newIP
					}
				}()
			}

			go func() {
				wg.Wait()
				close(newIPs)
			}()

			addedIPs := make([]string, 0, batchTarget)
			for ip := range newIPs {
				addedIPs = append(addedIPs, ip)
			}

			if len(addedIPs) > 0 {
				poolMutex.Lock()
				ipPool = append(ipPool, addedIPs...)
				fmt.Printf("Added %d IPs to pool. Pool size now: %d\n", len(addedIPs), len(ipPool))
				poolMutex.Unlock()
			}
		}
	}
}

func checkPrivileges() bool {
	if os.Geteuid() != 0 && ListenPort < 1024 {
		fmt.Println("ERROR: This program requires root privileges to bind to port 80 and add IPv6 addresses. Run with sudo or change ListenPort to a value above 1024.")
		return false
	}
	return true
}

func onStartup() bool {
	if !checkPrivileges() {
		return false
	}

	checkInterface()
	testIP := randomIPv6()
	if !addIPv6ToInterface(testIP) {
		fmt.Println("WARNING: Failed to add IPv6 address for testing. Some features may not work.")
	}

	fmt.Println("Startup checks completed")
	return true
}

func handleM3U8Proxy(w http.ResponseWriter, r *http.Request) {
	apiToken := r.Header.Get("API-Token")
	userAgent := r.Header.Get("User-Agent")

	if !validateAPIToken(apiToken, userAgent) {
		http.Error(w, "Unauthorized: i6.shark detected invalid API-Token.", http.StatusUnauthorized)
		return
	}

	logRequest(r)

	if Debug {
		fmt.Printf("Raw query string: %s\n", r.URL.RawQuery)
	}

	// Get the target URL from the 'url' parameter
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "Missing 'url' parameter for m3u8 proxy.", http.StatusBadRequest)
		return
	}

	// Parse custom headers if provided
	headersJSON := r.URL.Query().Get("headers")
	var customHeaders map[string]string
	if headersJSON != "" {
		err := json.Unmarshal([]byte(headersJSON), &customHeaders)
		if err != nil {
			fmt.Println("Warning: Failed to parse 'headers' JSON. Ignoring.")
		} else if Debug {
			fmt.Printf("Parsed custom headers for m3u8 proxy: %v\n", customHeaders)
		}
	}

	// Get an IPv6 from the pool for the outgoing request
	sourceIP, poolErr := getNextIPFromPool()
	useSpecificIP := true
	var sourceNetIP net.IP

	if poolErr != nil {
		fmt.Printf("Warning: IP Pool empty or error, falling back to system default IP. Error: %v\n", poolErr)
		sourceIP = "System default (fallback)"
		useSpecificIP = false
	} else {
		sourceNetIP = net.ParseIP(sourceIP)
		if sourceNetIP == nil {
			fmt.Printf("ERROR: Failed to parse IP from pool: %s. Falling back.\n", sourceIP)
			sourceIP = "System default (fallback)"
			useSpecificIP = false
		} else {
			fmt.Printf("Using IP from pool for m3u8 proxy: %s\n", sourceIP)
		}
	}

	// Create request for the m3u8 content
	targetURL = ensureURLHasScheme(targetURL)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}

	// Apply custom headers
	for name, value := range customHeaders {
		req.Header.Set(name, value)
	}

	// Copy relevant headers from the original request
	for name, values := range r.Header {
		if name != "Host" && name != "API-Token" {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
	}

	// Setup client with specific source IP or default
	var client *http.Client
	if useSpecificIP {
		specificTransport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: sourceNetIP, Port: 0},
				Timeout:   RequestTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   5,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		client = &http.Client{
			Transport: specificTransport,
			Timeout:   RequestTimeout,
		}
	} else {
		client = defaultClient
	}

	// Fetch the m3u8 content
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("ERROR using source IP %s for m3u8 %s: %v\n", sourceIP, targetURL, err)
		http.Error(w, fmt.Sprintf("Error fetching m3u8 content: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Upstream server returned status: %d", resp.StatusCode), resp.StatusCode)
		return
	}

	// Read the m3u8 content
	content, err := io.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error reading m3u8 content: %v", err), http.StatusInternalServerError)
		return
	}

	// Parse the URL to use as base for relative URLs
	parsedURL, err := url.Parse(targetURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error parsing target URL: %v", err), http.StatusInternalServerError)
		return
	}

	// Build the base URL for the proxy server
	proxyBaseURL := fmt.Sprintf("http://%s", r.Host)
	headersParam := ""
	if headersJSON != "" {
		headersParam = "&headers=" + url.QueryEscape(headersJSON)
	}

	// Process the m3u8 content
	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")
	newLines := make([]string, 0, len(lines))
	
	// Check if this is a master playlist (contains RESOLUTION or BANDWIDTH)
	isMaster := strings.Contains(contentStr, "RESOLUTION=") || strings.Contains(contentStr, "BANDWIDTH=")
	
	var currentDirective string
	
	for i, line := range lines {
		trimmedLine := strings.TrimSpace(line)
		if trimmedLine == "" {
			// Preserve empty lines
			newLines = append(newLines, "")
			continue
		}

		if strings.HasPrefix(trimmedLine, "#") {
			// Handle directives
			if strings.HasPrefix(trimmedLine, "#EXT-X-STREAM-INF:") || 
			   strings.HasPrefix(trimmedLine, "#EXT-X-MEDIA:") ||
			   strings.HasPrefix(trimmedLine, "#EXTINF:") {
				currentDirective = trimmedLine
			}
			
			if strings.HasPrefix(trimmedLine, "#EXT-X-KEY:") {
				// Replace the URL in key directives
				newLine := replaceURLInDirective(trimmedLine, parsedURL, proxyBaseURL, "/ts-proxy?url=", headersJSON)
				newLines = append(newLines, newLine)
			} else if strings.HasPrefix(trimmedLine, "#EXT-X-MEDIA:") {
				// Replace the URL in media directives
				newLine := replaceURLInDirective(trimmedLine, parsedURL, proxyBaseURL, "/m3u8-proxy?url=", headersJSON)
				newLines = append(newLines, newLine)
			} else {
				// Keep other directives unchanged
				newLines = append(newLines, trimmedLine)
			}
		} else {
			// Handle content lines (segment URLs)
			segmentURL, err := resolveURL(parsedURL, trimmedLine)
			if err != nil {
				fmt.Printf("Warning: Could not resolve segment URL %s: %v\n", trimmedLine, err)
				newLines = append(newLines, trimmedLine)
				continue
			}

			var proxyEndpoint string
			// Determine if this segment is another playlist or a media segment
			if isMaster || strings.HasSuffix(strings.ToLower(trimmedLine), ".m3u8") {
				proxyEndpoint = "/m3u8-proxy?url="
			} else {
				proxyEndpoint = "/ts-proxy?url="
			}
			
			newURL := fmt.Sprintf("%s%s%s%s", proxyBaseURL, proxyEndpoint, url.QueryEscape(segmentURL), headersParam)
			newLines = append(newLines, newURL)
			
			// Reset current directive
			currentDirective = ""
		}
	}

	// Set appropriate headers
	w.Header().Set("Content-Type", "application/vnd.apple.mpegurl")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	
	// Send the modified content
	w.Write([]byte(strings.Join(newLines, "\n")))
}

func handleTSProxy(w http.ResponseWriter, r *http.Request) {
	apiToken := r.Header.Get("API-Token")
	userAgent := r.Header.Get("User-Agent")

	if !validateAPIToken(apiToken, userAgent) {
		http.Error(w, "Unauthorized: i6.shark detected invalid API-Token.", http.StatusUnauthorized)
		return
	}

	logRequest(r)

	// Get the target URL from the 'url' parameter
	targetURL := r.URL.Query().Get("url")
	if targetURL == "" {
		http.Error(w, "Missing 'url' parameter for TS proxy.", http.StatusBadRequest)
		return
	}

	// Parse custom headers if provided
	headersJSON := r.URL.Query().Get("headers")
	var customHeaders map[string]string
	if headersJSON != "" {
		err := json.Unmarshal([]byte(headersJSON), &customHeaders)
		if err != nil {
			fmt.Println("Warning: Failed to parse 'headers' JSON. Ignoring.")
		} else if Debug {
			fmt.Printf("Parsed custom headers for TS proxy: %v\n", customHeaders)
		}
	}

	// Get an IPv6 from the pool for the outgoing request
	sourceIP, poolErr := getNextIPFromPool()
	useSpecificIP := true
	var sourceNetIP net.IP

	if poolErr != nil {
		fmt.Printf("Warning: IP Pool empty or error, falling back to system default IP. Error: %v\n", poolErr)
		sourceIP = "System default (fallback)"
		useSpecificIP = false
	} else {
		sourceNetIP = net.ParseIP(sourceIP)
		if sourceNetIP == nil {
			fmt.Printf("ERROR: Failed to parse IP from pool: %s. Falling back.\n", sourceIP)
			sourceIP = "System default (fallback)"
			useSpecificIP = false
		} else {
			fmt.Printf("Using IP from pool for TS proxy: %s\n", sourceIP)
		}
	}

	// Create request for the TS content
	targetURL = ensureURLHasScheme(targetURL)
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error creating request: %v", err), http.StatusInternalServerError)
		return
	}

	// Apply custom headers
	for name, value := range customHeaders {
		req.Header.Set(name, value)
	}

	// Copy relevant headers from the original request
	for name, values := range r.Header {
		if name != "Host" && name != "API-Token" {
			for _, value := range values {
				req.Header.Add(name, value)
			}
		}
	}

	// Setup client with specific source IP or default
	var client *http.Client
	if useSpecificIP {
		specificTransport := &http.Transport{
			Proxy: http.ProxyFromEnvironment,
			DialContext: (&net.Dialer{
				LocalAddr: &net.TCPAddr{IP: sourceNetIP, Port: 0},
				Timeout:   RequestTimeout,
				KeepAlive: 30 * time.Second,
			}).DialContext,
			ForceAttemptHTTP2:     true,
			MaxIdleConns:          10,
			MaxIdleConnsPerHost:   5,
			IdleConnTimeout:       60 * time.Second,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: 1 * time.Second,
		}
		client = &http.Client{
			Transport: specificTransport,
			Timeout:   RequestTimeout,
		}
	} else {
		client = defaultClient
	}

	fmt.Printf("TS proxy connecting to %s using source IP %s...\n", targetURL, sourceIP)
	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("ERROR using source IP %s for TS %s: %v\n", sourceIP, targetURL, err)
		http.Error(w, fmt.Sprintf("Error fetching TS content: %v", err), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		http.Error(w, fmt.Sprintf("Upstream server returned status: %d", resp.StatusCode), resp.StatusCode)
		return
	}

	// Set appropriate CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "*")
	w.Header().Set("Access-Control-Allow-Headers", "*")
	
	// Set content type for TS files
	w.Header().Set("Content-Type", "video/mp2t")
	
	// Copy any useful headers from the response
	for name, values := range resp.Header {
		if !skipHeaders[strings.ToLower(name)] {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
	}
	
	// Stream the response body to the client
	w.WriteHeader(resp.StatusCode)
	_, err = io.Copy(w, resp.Body)
	if err != nil {
		fmt.Printf("Error streaming TS content: %v\n", err)
	}
}

// Helper function to replace URLs in directives like EXT-X-KEY or EXT-X-MEDIA
func replaceURLInDirective(directive string, baseURL *url.URL, proxyBaseURL, proxyEndpoint, headersJSON string) string {
	// Find any URL in the directive
	urlRegex := regexp.MustCompile(`URI="([^"]+)"`)
	matches := urlRegex.FindStringSubmatch(directive)
	
	if len(matches) < 2 {
		return directive
	}

	// Resolve the URL if it's relative
	originalURL := matches[1]
	resolvedURL, err := resolveURL(baseURL, originalURL)
	if err != nil {
		fmt.Printf("Warning: Could not resolve URL in directive %s: %v\n", directive, err)
		return directive
	}

	// Create the proxied URL
	headersParam := ""
	if headersJSON != "" {
		headersParam = "&headers=" + url.QueryEscape(headersJSON)
	}
	
	proxiedURL := fmt.Sprintf("%s%s%s%s", proxyBaseURL, proxyEndpoint, url.QueryEscape(resolvedURL), headersParam)
	
	// Replace the URL in the directive
	return strings.Replace(directive, fmt.Sprintf(`URI="%s"`, originalURL), fmt.Sprintf(`URI="%s"`, proxiedURL), 1)
}

// Helper function to resolve a URL that might be relative
func resolveURL(baseURL *url.URL, urlStr string) (string, error) {
	parsedURL, err := url.Parse(urlStr)
	if err != nil {
		return "", err
	}
	
	// If the URL is already absolute, return it
	if parsedURL.IsAbs() {
		return urlStr, nil
	}
	
	// Otherwise, resolve it against the base URL
	return baseURL.ResolveReference(parsedURL).String(), nil
}

func main() {
	random = rand.New(rand.NewSource(time.Now().UnixNano()))
	ipPool = make([]string, 0, DesiredPoolSize)
	currentIPIndex = 0

	defaultTransport = &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   RequestTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          200,
		MaxIdleConnsPerHost:   100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	defaultClient = &http.Client{
		Transport: defaultTransport,
		Timeout:   RequestTimeout,
	}

	if !onStartup() {
		os.Exit(1)
	}

	go manageIPPool()
	http.HandleFunc("/", handleRequest)
	http.HandleFunc("/m3u8-proxy", handleM3U8Proxy)
	http.HandleFunc("/ts-proxy", handleTSProxy)

	listenAddr := fmt.Sprintf("%s:%d", ListenHost, ListenPort)
	fmt.Printf("Starting i6.shark server on %s\n", listenAddr)
	err := http.ListenAndServe(listenAddr, nil)
	if err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}

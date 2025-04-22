package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// getLocalAddr selects an IP address from the specified interface.
func getLocalAddr(interfaceName string, ipv4Only, ipv6Only bool) (net.Addr, error) {
	if interfaceName == "" {
		return nil, nil // No interface specified, use default
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %q: %w", interfaceName, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %q: %w", interfaceName, err)
	}

	var selectedIP net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		isIPv4 := ip.To4() != nil
		isIPv6 := !isIPv4

		if ipv4Only && isIPv4 {
			selectedIP = ip
			break // Prefer first match
		} else if ipv6Only && isIPv6 {
			// Ensure it's not a link-local address unless it's the only option
			if !ip.IsLinkLocalUnicast() {
				selectedIP = ip
				break
			} else if selectedIP == nil { // Keep link-local only if nothing else found yet
				selectedIP = ip
			}
		} else if !ipv4Only && !ipv6Only { // No specific protocol forced
			// Prefer non-link-local IPv6 first, then IPv4, then link-local IPv6
			if isIPv6 && !ip.IsLinkLocalUnicast() {
				selectedIP = ip
				break
			} else if isIPv4 {
				if selectedIP == nil || (selectedIP != nil && selectedIP.IsLinkLocalUnicast()) {
					selectedIP = ip // Prefer IPv4 over link-local IPv6
				}
			} else if isIPv6 && ip.IsLinkLocalUnicast() && selectedIP == nil {
				selectedIP = ip // Fallback to link-local IPv6
			}
		}
	}

	if selectedIP == nil {
		return nil, fmt.Errorf("no suitable IP address found for interface %q (ipv4Only=%v, ipv6Only=%v)", interfaceName, ipv4Only, ipv6Only)
	}

	// Create a TCPAddr with the selected IP and port 0
	return &net.TCPAddr{IP: selectedIP, Port: 0}, nil
}

func NewHTTPClient(ipv4Only, ipv6Only bool, interfaceName string) (*http.Client, error) { // Added interfaceName, return error
	localAddr, err := getLocalAddr(interfaceName, ipv4Only, ipv6Only)
	if err != nil {
		return nil, fmt.Errorf("failed to determine local address for interface %q: %w", interfaceName, err)
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: localAddr, // Set the local address for binding
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	transport := &http.Transport{
		// Use the pre-configured dialer in DialContext
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			networkPreference := "tcp" // Default network type
			if ipv4Only {
				networkPreference = "tcp4"
			} else if ipv6Only {
				networkPreference = "tcp6"
			}

			// If LocalAddr forces a specific IP version, ensure networkPreference matches
			if tcpAddr, ok := dialer.LocalAddr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
				if tcpAddr.IP.To4() != nil {
					networkPreference = "tcp4"
				} else {
					networkPreference = "tcp6"
				}
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			// If host is already an IP, just dial it using the configured dialer
			if ip := net.ParseIP(host); ip != nil {
				isIPv4 := ip.To4() != nil
				// Check if IP version matches preference forced by flags or local address
				if (networkPreference == "tcp4" && !isIPv4) || (networkPreference == "tcp6" && isIPv4) {
					return nil, fmt.Errorf("IP address %s does not match required network type %s", host, networkPreference)
				}
				// Use the dialer which has LocalAddr set
				conn, dialErr := dialer.DialContext(ctx, networkPreference, net.JoinHostPort(ip.String(), port))
				if dialErr != nil {
					errMsg := fmt.Sprintf("failed to dial IP %s:%s", ip.String(), port)
					if interfaceName != "" {
						errMsg = fmt.Sprintf("%s using interface %q", errMsg, interfaceName)
					}
					errMsg = fmt.Sprintf("%s: %v", errMsg, dialErr)
					return nil, fmt.Errorf(errMsg)
				}
				return conn, nil
			}

			// Resolve hostname using the multi-stage resolver
			resolvedIPs, resolveErr := resolveHost(ctx, host, ipv4Only, ipv6Only)
			if resolveErr != nil {
				return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, resolveErr)
			}
			if len(resolvedIPs) == 0 {
				return nil, fmt.Errorf("DNS resolution failed: no IPs returned for %s", host)
			}

			// Try dialing resolved IPs using the configured dialer
			var firstDialErr error
			for _, ip := range resolvedIPs {
				ipStr := ip.String()
				isIPv4 := ip.To4() != nil

				// Ensure IP matches network preference forced by flags or local address
				// This check is now more critical as resolveHost might return mixed IPs if flags aren't set
				if (networkPreference == "tcp4" && !isIPv4) || (networkPreference == "tcp6" && isIPv4) {
					continue // Skip this IP as it doesn't match the required network type
				}

				// Use the dialer with the potentially set LocalAddr
				conn, dialErr := dialer.DialContext(ctx, networkPreference, net.JoinHostPort(ipStr, port))
				if dialErr == nil {
					return conn, nil // Success
				}
				if firstDialErr == nil {
					firstDialErr = dialErr // Store the first error encountered
				}
			}

			// If all attempts failed
			errMsg := fmt.Sprintf("connection failed to all resolved IPs for %s:%s", host, port)
			if firstDialErr != nil {
				errMsg = fmt.Sprintf("%s (last dial error: %v)", errMsg, firstDialErr)
			}
			if interfaceName != "" {
				errMsg = fmt.Sprintf("%s using interface %s", errMsg, interfaceName)
			}
			return nil, fmt.Errorf(errMsg)

		},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
		TLSClientConfig: &tls.Config{
			RootCAs:    rootCAs,
			ServerName: "speed.cloudflare.com", // Set SNI explicitly
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second, // Keep overall client timeout
	}, nil // Return nil error on success
}

// resolveHost attempts to resolve a hostname using DoH, then system DNS, then direct DNS queries.
func resolveHost(ctx context.Context, host string, ipv4Only, ipv6Only bool) ([]net.IP, error) {
	var lastErr error
	var ips []net.IP

	// Attempt 1: DoH
	ips, err := resolveWithDoH(ctx, host, ipv4Only, ipv6Only)
	if err == nil && len(ips) > 0 {
		return ips, nil // DoH succeeded
	}
	if err != nil {
		// Log DoH failure (consider using a proper logger)
		// fmt.Fprintf(os.Stderr, "Debug: DoH resolution failed for %s: %v\n", host, err)
		lastErr = fmt.Errorf("DoH failed: %w", err)
	} else {
		lastErr = errors.New("DoH failed: no IPs returned")
	}

	// Attempt 2: System Resolver
	resolver := net.Resolver{}
	ipAddrs, err := resolver.LookupIPAddr(ctx, host)
	if err == nil && len(ipAddrs) > 0 {
		ips = ips[:0] // Clear any previous empty slice
		for _, ipAddr := range ipAddrs {
			isIPv4 := ipAddr.IP.To4() != nil
			if ipv4Only && !isIPv4 {
				continue
			}
			if ipv6Only && isIPv4 {
				continue
			}
			ips = append(ips, ipAddr.IP)
		}
		if len(ips) > 0 {
			return ips, nil // System resolver succeeded
		}
		// If system resolver returned IPs but none matched the filter
		err = fmt.Errorf("system resolver returned IPs, but none matched filter (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
	}
	if err != nil {
		// Log system resolver failure
		// fmt.Fprintf(os.Stderr, "Debug: System DNS resolution failed for %s: %v\n", host, err)
		lastErr = fmt.Errorf("%v; System DNS failed: %w", lastErr, err)
	} else if len(ipAddrs) == 0 {
		lastErr = fmt.Errorf("%v; System DNS failed: no IPs returned", lastErr)
	}

	// Attempt 3: Direct DNS
	ips, err = resolveWithDirectDNS(ctx, host, ipv4Only, ipv6Only)
	if err == nil && len(ips) > 0 {
		return ips, nil // Direct DNS succeeded
	}
	if err != nil {
		// Log direct DNS failure
		// fmt.Fprintf(os.Stderr, "Debug: Direct DNS resolution failed for %s: %v\n", host, err)
		lastErr = fmt.Errorf("%v; Direct DNS failed: %w", lastErr, err)
	} else if len(ips) == 0 && lastErr != nil {
		// If direct DNS returned no IPs but we had a previous error, keep the error chain
		lastErr = fmt.Errorf("%v; Direct DNS failed: no IPs returned", lastErr)
	} else if lastErr == nil { // Only set this error if Direct DNS was the first to fail
		lastErr = errors.New("Direct DNS failed: no IPs returned")
	}

	// All methods failed
	return nil, fmt.Errorf("all resolution methods failed for %s: %w", host, lastErr)
}

// resolveWithDoH tries to resolve using DNS over HTTPS.
func resolveWithDoH(ctx context.Context, host string, ipv4Only, ipv6Only bool) ([]net.IP, error) {
	dohServers := []struct {
		address string // e.g., "1.1.1.1:443"
		sni     string // e.g., "cloudflare-dns.com"
		isV4    bool
	}{
		{"1.1.1.1:443", "cloudflare-dns.com", true},
		{"1.0.0.1:443", "cloudflare-dns.com", true},
		{"8.8.8.8:443", "dns.google", true},    // Google DoH
		{"8.8.4.4:443", "dns.google", true},    // Google DoH
		{"9.9.9.9:443", "dns.quad9.net", true}, // Quad9 DoH
		{"2606:4700:4700::1111:443", "cloudflare-dns.com", false},
		{"2606:4700:4700::1001:443", "cloudflare-dns.com", false},
		{"2001:4860:4860::8888:443", "dns.google", false}, // Google DoH IPv6
		{"2001:4860:4860::8844:443", "dns.google", false}, // Google DoH IPv6
		{"2620:fe::fe:443", "dns.quad9.net", false},       // Quad9 DoH IPv6
	}

	// Shuffle servers to distribute load and avoid hitting the same failing one first
	rand.Shuffle(len(dohServers), func(i, j int) {
		dohServers[i], dohServers[j] = dohServers[j], dohServers[i]
	})

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		rootCAs = x509.NewCertPool()
	}

	var ips []net.IP
	var queryTypes []uint16

	switch {
	case ipv4Only:
		queryTypes = []uint16{dns.TypeA}
	case ipv6Only:
		queryTypes = []uint16{dns.TypeAAAA}
	default:
		queryTypes = []uint16{dns.TypeA, dns.TypeAAAA}
	}

	var lastErr error
	var wg sync.WaitGroup
	var mu sync.Mutex // Protects ips and lastErr

	processedQueryType := make(map[uint16]bool)

	for _, qtype := range queryTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		m.RecursionDesired = true

		msg, err := m.Pack()
		if err != nil {
			mu.Lock()
			lastErr = fmt.Errorf("failed to pack DNS query type %d: %w (last error: %v)", qtype, err, lastErr)
			mu.Unlock()
			continue // Try next query type if packing fails
		}
		b64 := base64.RawURLEncoding.EncodeToString(msg)

		// Try multiple DoH servers concurrently for the same query type
		queryCtx, queryCancel := context.WithCancel(ctx) // Context to cancel other servers once one succeeds for this qtype
		defer queryCancel()                              // Ensure cleanup

		for _, server := range dohServers {
			// Skip server if its IP version doesn't match the forced flag, if any.
			if (ipv4Only && !server.isV4) || (ipv6Only && server.isV4) {
				continue
			}

			wg.Add(1)
			go func(server struct {
				address, sni string
				isV4         bool
			}) {
				defer wg.Done()
				select {
				case <-queryCtx.Done(): // Check if another goroutine succeeded for this qtype
					return
				default:
				}

				// Create a temporary, short-lived client *per attempt* for DoH request
				dialer := &net.Dialer{Timeout: 3 * time.Second} // Slightly increased timeout
				dohTransport := &http.Transport{
					TLSClientConfig: &tls.Config{
						ServerName: server.sni,
						RootCAs:    rootCAs,
					},
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						dohNet := "tcp4"
						if !server.isV4 {
							dohNet = "tcp6"
						}
						// Use a context with timeout for the dial itself
						dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
						defer dialCancel()
						return dialer.DialContext(dialCtx, dohNet, server.address)
					},
					DisableKeepAlives: true,
					ForceAttemptHTTP2: true, // Try HTTP/2
				}
				dohClient := &http.Client{
					Transport: dohTransport,
					Timeout:   5 * time.Second, // Overall timeout for the DoH request
				}
				reqCtx, cancel := context.WithTimeout(queryCtx, 5*time.Second) // Timeout for this specific request attempt
				defer cancel()
				req, err := http.NewRequestWithContext(reqCtx, "GET", fmt.Sprintf("https://%s/dns-query?dns=%s", server.sni, b64), nil)
				if err != nil {
					mu.Lock()
					lastErr = fmt.Errorf("failed creating DoH request to %s (%s): %w (last error: %v)", server.sni, server.address, err, lastErr)
					mu.Unlock()
					return
				}
				req.Header.Set("Accept", "application/dns-message")
				resp, err := dohClient.Do(req)
				if err != nil {
					mu.Lock()
					// Add context deadline exceeded info if applicable
					errStr := fmt.Sprintf("DoH request to %s (%s) failed: %v", server.sni, server.address, err)
					if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
						errStr += " (timeout)"
					}
					lastErr = fmt.Errorf("%s (last error: %v)", errStr, lastErr)
					mu.Unlock()
					return
				}
				defer resp.Body.Close() // Ensure body is closed

				if resp.StatusCode != http.StatusOK {
					mu.Lock()
					lastErr = fmt.Errorf("DoH request to %s (%s) returned status %d (last error: %v)", server.sni, server.address, resp.StatusCode, lastErr)
					mu.Unlock()
					return
				}
				body, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					mu.Lock()
					lastErr = fmt.Errorf("failed reading DoH response body from %s (%s): %w (last error: %v)", server.sni, server.address, readErr, lastErr)
					mu.Unlock()
					return
				}
				response := new(dns.Msg)
				if err := response.Unpack(body); err != nil {
					mu.Lock()
					lastErr = fmt.Errorf("failed unpacking DoH response from %s (%s): %w (last error: %v)", server.sni, server.address, err, lastErr)
					mu.Unlock()
					return
				}

				// Process answers
				mu.Lock()
				initialLen := len(ips)
				for _, ans := range response.Answer {
					switch a := ans.(type) {
					case *dns.A:
						if !ipv6Only { // Add A if IPv6 is not exclusively requested
							ips = append(ips, a.A)
						}
					case *dns.AAAA:
						if !ipv4Only { // Add AAAA if IPv4 is not exclusively requested
							ips = append(ips, a.AAAA)
						}
					}
				}

				// If we successfully added IPs of the type we were looking for, mark type as processed and cancel others
				if len(ips) > initialLen {
					foundRelevantIP := false
					for i := initialLen; i < len(ips); i++ {
						isIPv4 := ips[i].To4() != nil
						if (qtype == dns.TypeA && isIPv4) || (qtype == dns.TypeAAAA && !isIPv4) {
							foundRelevantIP = true
							break
						}
					}
					if foundRelevantIP && !processedQueryType[qtype] {
						processedQueryType[qtype] = true
						queryCancel() // Cancel other goroutines for this query type
					}
				}
				mu.Unlock()
			}(server) // Pass server info by value
		}
		wg.Wait() // Wait for all servers for this query type to finish or be cancelled

		// Check if we have the results we need after this query type
		mu.Lock()
		if len(ips) > 0 {
			hasIPv4 := false
			hasIPv6 := false
			for _, ip := range ips {
				if ip.To4() != nil {
					hasIPv4 = true
				} else {
					hasIPv6 = true
				}
			}
			// If only one type was needed and we have it, stop early
			if (ipv4Only && hasIPv4) || (ipv6Only && hasIPv6) {
				mu.Unlock()
				break // Break the outer query type loop
			}
			// If both were allowed, and we have found at least one of each, we can also potentially stop
			// (though iterating might find more/better options). Let's continue for now.
		}
		mu.Unlock()

	} // End of query type loop

	mu.Lock()
	defer mu.Unlock()
	if len(ips) > 0 {
		// Filter final list one more time based on flags, as mixed results might exist if flags weren't strict
		filteredIPs := ips[:0]
		for _, ip := range ips {
			isIPv4 := ip.To4() != nil
			if (ipv4Only && !isIPv4) || (ipv6Only && isIPv4) {
				continue
			}
			filteredIPs = append(filteredIPs, ip)
		}
		if len(filteredIPs) > 0 {
			return filteredIPs, nil
		}
		// If filtering removed all IPs, report error
		lastErr = fmt.Errorf("DoH returned IPs, but none matched filter (ipv4=%v, ipv6=%v) (last error: %v)", ipv4Only, ipv6Only, lastErr)

	}

	// If no IPs found
	if lastErr != nil {
		return nil, fmt.Errorf("all DoH attempts failed for %s: %w", host, lastErr)
	}
	return nil, fmt.Errorf("DoH attempts failed, no IPs resolved for %s", host)
}

// resolveWithDirectDNS attempts to resolve using standard DNS queries to public resolvers.
func resolveWithDirectDNS(ctx context.Context, host string, ipv4Only, ipv6Only bool) ([]net.IP, error) {
	servers := []struct {
		addr string
		isV4 bool
	}{
		// Cloudflare
		{"1.1.1.1:53", true},
		{"1.0.0.1:53", true},
		{"[2606:4700:4700::1111]:53", false},
		{"[2606:4700:4700::1001]:53", false},
		// Google
		{"8.8.8.8:53", true},
		{"8.8.4.4:53", true},
		{"[2001:4860:4860::8888]:53", false},
		{"[2001:4860:4860::8844]:53", false},
		// Quad9
		{"9.9.9.9:53", true},
		{"[2620:fe::fe]:53", false},
	}

	// Shuffle servers
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})

	var queryTypes []uint16
	switch {
	case ipv4Only:
		queryTypes = []uint16{dns.TypeA}
	case ipv6Only:
		queryTypes = []uint16{dns.TypeAAAA}
	default:
		queryTypes = []uint16{dns.TypeA, dns.TypeAAAA}
	}

	var ips []net.IP
	var lastErr error
	var wg sync.WaitGroup
	var mu sync.Mutex // Protects ips and lastErr

	processedQueryType := make(map[uint16]bool)

	// Create clients once
	dnsClientUDP := &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	dnsClientTCP := &dns.Client{Net: "tcp", Timeout: 3 * time.Second} // Slightly longer timeout for TCP

	for _, qtype := range queryTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		m.RecursionDesired = true
		m.SetEdns0(4096, true) // Request EDNS for larger UDP responses

		queryCtx, queryCancel := context.WithCancel(ctx) // Context for this query type
		defer queryCancel()

		for _, server := range servers {
			// Skip server if its IP version doesn't match the forced flag
			if (ipv4Only && !server.isV4) || (ipv6Only && server.isV4) {
				continue
			}

			wg.Add(1)
			go func(serverAddr string) {
				defer wg.Done()
				select {
				case <-queryCtx.Done():
					return // Stop if another goroutine succeeded for this type
				default:
				}

				var response *dns.Msg
				var err error
				var rtt time.Duration // Unused but returned by ExchangeContext
				attemptedTCP := false

				// Try UDP first
				response, rtt, err = dnsClientUDP.ExchangeContext(queryCtx, m, serverAddr)

				// Check conditions for TCP retry: network error, timeout, or truncated response
				// Note: The dns library *might* retry automatically on truncation if Exchange is used,
				// but ExchangeContext might not. Explicitly retrying is safer.
				needsTCPRetry := false
				if err != nil {
					// Check for specific network errors or timeouts that might warrant a TCP retry
					var netErr net.Error
					if errors.As(err, &netErr) && (netErr.Timeout() || netErr.Temporary()) {
						needsTCPRetry = true
					} else if errors.Is(err, context.DeadlineExceeded) {
						// Treat context deadline as a timeout for retry purposes
						needsTCPRetry = true
					}
					// Add other specific errors if needed
				} else if response != nil && response.Truncated {
					needsTCPRetry = true
				}

				// Retry with TCP if needed and not already successful
				if needsTCPRetry && (response == nil || response.Rcode != dns.RcodeSuccess) {
					attemptedTCP = true
					response, rtt, err = dnsClientTCP.ExchangeContext(queryCtx, m, serverAddr)
				}

				// --- Process the final result (either UDP or TCP) ---

				if err != nil || (response != nil && response.Rcode != dns.RcodeSuccess) {
					mu.Lock()
					protocol := "UDP"
					if attemptedTCP {
						protocol = "TCP"
					}
					errStr := fmt.Sprintf("direct DNS %s query to %s failed: %v", protocol, serverAddr, err)
					if response != nil && response.Rcode != dns.RcodeSuccess {
						errStr += fmt.Sprintf(" (RCODE: %s)", dns.RcodeToString[response.Rcode])
					}
					if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
						errStr += " (timeout)"
					}
					lastErr = fmt.Errorf("%s (last error: %v)", errStr, lastErr)
					mu.Unlock()
					return // Query failed
				}

				// Process successful response
				_ = rtt // RTT not used currently
				mu.Lock()
				initialLen := len(ips)
				for _, ans := range response.Answer {
					switch a := ans.(type) {
					case *dns.A:
						if !ipv6Only {
							ips = append(ips, a.A)
						}
					case *dns.AAAA:
						if !ipv4Only {
							ips = append(ips, a.AAAA)
						}
					}
				}

				if len(ips) > initialLen {
					foundRelevantIP := false
					for i := initialLen; i < len(ips); i++ {
						isIPv4 := ips[i].To4() != nil
						if (qtype == dns.TypeA && isIPv4) || (qtype == dns.TypeAAAA && !isIPv4) {
							foundRelevantIP = true
							break
						}
					}
					if foundRelevantIP && !processedQueryType[qtype] {
						processedQueryType[qtype] = true
						queryCancel() // Cancel others for this query type
					}
				}
				mu.Unlock()

			}(server.addr) // Pass server address by value
		}
		wg.Wait() // Wait for all direct DNS attempts for this qtype

		// Check if we have the needed results
		mu.Lock()
		if len(ips) > 0 {
			hasIPv4 := false
			hasIPv6 := false
			for _, ip := range ips {
				if ip.To4() != nil {
					hasIPv4 = true
				} else {
					hasIPv6 = true
				}
			}
			if (ipv4Only && hasIPv4) || (ipv6Only && hasIPv6) {
				mu.Unlock()
				break // Stop querying other types
			}
		}
		mu.Unlock()
	} // End query type loop

	mu.Lock()
	defer mu.Unlock()

	if len(ips) > 0 {
		// Filter final list one more time based on flags
		filteredIPs := ips[:0]
		for _, ip := range ips {
			isIPv4 := ip.To4() != nil
			if (ipv4Only && !isIPv4) || (ipv6Only && isIPv4) {
				continue
			}
			filteredIPs = append(filteredIPs, ip)
		}
		if len(filteredIPs) > 0 {
			return filteredIPs, nil
		}
		// If filtering removed all IPs, report error
		lastErr = fmt.Errorf("direct DNS returned IPs, but none matched filter (ipv4=%v, ipv6=%v) (last error: %v)", ipv4Only, ipv6Only, lastErr)
	}

	if lastErr != nil {
		return nil, fmt.Errorf("all direct DNS attempts failed for %s: %w", host, lastErr)
	}
	return nil, fmt.Errorf("direct DNS attempts failed, no IPs resolved for %s", host)
}

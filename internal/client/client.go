package client

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/gwatts/rootcerts"
	"github.com/miekg/dns"
)

// getEffectiveRootCAs attempts to load system CAs and falls back to embedded ones.
func getEffectiveRootCAs() *x509.CertPool {
	sysPool, err := x509.SystemCertPool()
	if err != nil {
		log.Printf("Warning: Failed to load system root CA pool: %v. Using embedded certs as fallback.\n", err)
		// Fallback to embedded CAs
		return rootcerts.ServerCertPool()
	}
	if sysPool == nil {
		log.Printf("Warning: System root CA pool is nil. Using embedded certs as fallback.\n")
		// Fallback to embedded CAs if system returned nil without error
		return rootcerts.ServerCertPool()
	}
	// Use system CAs if loaded successfully
	return sysPool
}

// getLocalAddr selects an IP address from the specified interface or returns a direct TCPAddr if an IP is provided.
func getLocalAddr(interfaceOrIP string, ipv4Only, ipv6Only bool) (net.Addr, error) {
	if interfaceOrIP == "" {
		return nil, nil // No interface or IP specified, use default binding
	}

	// Check if interfaceOrIP is actually an IP address first
	if ip := net.ParseIP(interfaceOrIP); ip != nil {
		// It's an IP address, create TCPAddr directly
		// Ensure the IP family matches the flags if provided
		isIPv4 := ip.To4() != nil
		if ipv4Only && !isIPv4 {
			return nil, fmt.Errorf("provided IP %s is not IPv4, but --ipv4 flag was specified", interfaceOrIP)
		}
		if ipv6Only && isIPv4 {
			return nil, fmt.Errorf("provided IP %s is not IPv6, but --ipv6 flag was specified", interfaceOrIP)
		}
		return &net.TCPAddr{IP: ip, Port: 0}, nil
	}

	// If not an IP, treat as an interface name
	iface, err := net.InterfaceByName(interfaceOrIP)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %q: %w", interfaceOrIP, err)
	}

	addrs, err := iface.Addrs()
	if err != nil {
		return nil, fmt.Errorf("failed to get addresses for interface %q: %w", interfaceOrIP, err)
	}

	var selectedIP net.IP
	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok {
			continue
		}
		ip := ipNet.IP
		// Skip loopback and unspecified addresses
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
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
				if selectedIP == nil || (selectedIP.IsLinkLocalUnicast()) {
					selectedIP = ip // Prefer IPv4 over link-local IPv6
				}
			} else if isIPv6 && ip.IsLinkLocalUnicast() && selectedIP == nil {
				selectedIP = ip // Fallback to link-local IPv6
			}
		}
	}

	// Line 85: nilness check seems to be a false positive from some linters.
	// The selectedIP variable can indeed be nil here if no suitable IP is found.
	if selectedIP == nil {
		family := "any"
		if ipv4Only {
			family = "IPv4"
		} else if ipv6Only {
			family = "IPv6"
		}
		return nil, fmt.Errorf("no suitable %s IP address found for interface %q", family, interfaceOrIP)
	}

	// Create a TCPAddr with the selected IP and port 0
	return &net.TCPAddr{IP: selectedIP, Port: 0}, nil
}

// NewHTTPClient creates a new HTTP client with options for IP version, interface binding, and TLS verification skipping.
func NewHTTPClient(ipv4Only, ipv6Only bool, interfaceOrIP string, insecureSkipVerify bool) (*http.Client, error) { // Renamed param for clarity
	localAddr, err := getLocalAddr(interfaceOrIP, ipv4Only, ipv6Only)
	if err != nil {
		// Don't wrap the error here, as it's already specific enough.
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: localAddr, // Set the local address for binding
	}

	// Get the effective root CA pool (system or embedded fallback)
	var effectiveRootCAs *x509.CertPool
	if !insecureSkipVerify {
		effectiveRootCAs = getEffectiveRootCAs()
	} else {
		// Explicitly set to nil if insecureSkipVerify is true, although
		// InsecureSkipVerify=true overrides RootCAs anyway.
		effectiveRootCAs = nil
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment, // Ensure proxy settings are respected
		// Use the pre-configured dialer in DialContext
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			networkPreference := "tcp" // Default network type
			if ipv4Only {
				networkPreference = "tcp4"
			} else if ipv6Only {
				networkPreference = "tcp6"
			}

			// If LocalAddr forces a specific IP version, update flags and preference
			if tcpAddr, ok := dialer.LocalAddr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
				if tcpAddr.IP.To4() != nil {
					if ipv6Only { // Conflict check
						return nil, fmt.Errorf("cannot bind to IPv4 address %s when --ipv6 is specified", tcpAddr.IP.String())
					}
					networkPreference = "tcp4"
					ipv4Only = true
					ipv6Only = false
				} else {
					if ipv4Only { // Conflict check
						return nil, fmt.Errorf("cannot bind to IPv6 address %s when --ipv4 is specified", tcpAddr.IP.String())
					}
					networkPreference = "tcp6"
					ipv6Only = true
					ipv4Only = false
				}
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			// If host is already an IP, just dial it using the configured dialer
			if ip := net.ParseIP(host); ip != nil {
				isIPv4 := ip.To4() != nil
				currentNetworkType := "tcp6"
				if isIPv4 {
					currentNetworkType = "tcp4"
				}

				// Check if IP version matches preference forced by flags or local address
				if (networkPreference == "tcp4" && !isIPv4) || (networkPreference == "tcp6" && isIPv4) {
					// This can happen if the address (e.g. speed.cloudflare.com:443) resolves
					// to an IP that doesn't match the required family.
					return nil, fmt.Errorf("target IP address %s does not match required network type %s", host, networkPreference)
				}
				// Use the dialer which has LocalAddr set
				conn, dialErr := dialer.DialContext(ctx, currentNetworkType, net.JoinHostPort(ip.String(), port))
				if dialErr != nil {
					errMsg := fmt.Sprintf("failed to dial IP %s:%s", ip.String(), port)
					if interfaceOrIP != "" {
						errMsg = fmt.Sprintf("%s using source %q", errMsg, interfaceOrIP)
					}
					if localAddr != nil {
						errMsg = fmt.Sprintf("%s from local addr %s", errMsg, localAddr.String())
					}
					errMsg = fmt.Sprintf("%s: %v", errMsg, dialErr)

					// Check for specific error types
					var opErr *net.OpError
					if errors.As(dialErr, &opErr) {
						if opErr.Op == "dial" && strings.Contains(opErr.Err.Error(), "invalid argument") {
							errMsg += " (Hint: Mismatch between IP family and interface/flags?)"
						} else if opErr.Op == "dial" && strings.Contains(opErr.Err.Error(), "cannot assign requested address") {
							errMsg += " (Hint: Source IP/interface might be incorrect or down)"
						}
					}
					return nil, errors.New(errMsg)
				}
				return conn, nil
			}

			// Resolve hostname using the multi-stage resolver
			// Pass insecureSkipVerify down to DoH resolver
			resolvedIPs, resolveErr := resolveHost(ctx, host, ipv4Only, ipv6Only, insecureSkipVerify, effectiveRootCAs) // Pass down effective CAs
			if resolveErr != nil {
				return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, resolveErr)
			}
			if len(resolvedIPs) == 0 {
				// This case should ideally be covered by resolveHost returning an error, but handle defensively
				return nil, fmt.Errorf("DNS resolution failed: no usable IPs returned for %s (ipv4=%v, ipv6=%v)", host, ipv4Only, ipv6Only)
			}

			// Try dialing resolved IPs using the configured dialer
			var firstDialErr error
			for _, ip := range resolvedIPs {
				ipStr := ip.String()
				isIPv4 := ip.To4() != nil

				// Determine the correct network type for this specific IP
				currentNetworkPreference := "tcp"
				if isIPv4 {
					currentNetworkPreference = "tcp4"
				} else {
					currentNetworkPreference = "tcp6"
				}

				// Ensure IP matches overall network preference forced by flags or local address
				// This check should already be handled by resolveHost filtering, but double-check
				if (networkPreference == "tcp4" && !isIPv4) || (networkPreference == "tcp6" && isIPv4) {
					log.Printf("Debug: Skipping resolved IP %s as it doesn't match required family %s\n", ipStr, networkPreference)
					continue // Skip this IP as it doesn't match the required network type
				}

				// Use the dialer with the potentially set LocalAddr
				// Dial using the specific network type for the resolved IP
				conn, dialErr := dialer.DialContext(ctx, currentNetworkPreference, net.JoinHostPort(ipStr, port))
				if dialErr == nil {
					return conn, nil // Success
				}
				if firstDialErr == nil {
					firstDialErr = dialErr // Store the first error encountered
				} else {
					// Optionally log subsequent errors for debugging
					// log.Printf("Debug: Dial attempt failed for %s:%s: %v", ipStr, port, dialErr)
				}
			}

			// If all attempts failed
			errMsg := fmt.Sprintf("connection failed to all resolved IPs for %s:%s", host, port)
			if firstDialErr != nil {
				// Check for specific error types in the first error
				var opErr *net.OpError
				if errors.As(firstDialErr, &opErr) {
					if opErr.Op == "dial" && strings.Contains(opErr.Err.Error(), "invalid argument") {
						errMsg += " (Hint: Mismatch between IP family and interface/flags?)"
					} else if opErr.Op == "dial" && strings.Contains(opErr.Err.Error(), "cannot assign requested address") {
						errMsg += " (Hint: Source IP/interface might be incorrect or down)"
					}
				}
				errMsg = fmt.Sprintf("%s (first dial error: %v)", errMsg, firstDialErr)
			}
			if interfaceOrIP != "" {
				errMsg = fmt.Sprintf("%s using source %s", errMsg, interfaceOrIP)
			}
			if localAddr != nil {
				errMsg = fmt.Sprintf("%s from local addr %s", errMsg, localAddr.String())
			}
			return nil, errors.New(errMsg)

		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second, // Add TLS handshake timeout
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		TLSClientConfig: &tls.Config{
			RootCAs:            effectiveRootCAs,       // Use the chosen pool (system or embedded)
			ServerName:         "speed.cloudflare.com", // Set SNI explicitly
			InsecureSkipVerify: insecureSkipVerify,     // Set based on the flag
		},
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second, // Keep overall client timeout
	}, nil // Return nil error on success
}

// resolveHost attempts to resolve a hostname using DoH, then system DNS, then direct DNS queries.
// Pass down the effective root CAs pool for DoH client configuration.
func resolveHost(ctx context.Context, host string, ipv4Only, ipv6Only bool, insecureSkipVerify bool, rootCAs *x509.CertPool) ([]net.IP, error) {
	var lastErr error
	var ips []net.IP

	// Attempt 1: DoH
	// Pass insecureSkipVerify and rootCAs down
	ips, err := resolveWithDoH(ctx, host, ipv4Only, ipv6Only, insecureSkipVerify, rootCAs)
	if err == nil && len(ips) > 0 {
		return ips, nil // DoH succeeded
	}
	if err != nil {
		log.Printf("Debug: DoH resolution failed for %s: %v\n", host, err)
		lastErr = fmt.Errorf("doH failed: %w", err)
	} else {
		// This case (err == nil but len(ips) == 0) means DoH completed but found no matching IPs.
		lastErr = fmt.Errorf("doH failed: no matching IPs found (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
	}

	// Attempt 2: System Resolver
	resolver := net.Resolver{}
	ipAddrs, err := resolver.LookupIPAddr(ctx, host)
	if err == nil && len(ipAddrs) > 0 {
		filteredSystemIPs := ipAddrs[:0] // Create a new slice for filtering
		for _, ipAddr := range ipAddrs {
			// Ensure IP is not unspecified (0.0.0.0 or ::) or loopback
			if ipAddr.IP.IsUnspecified() || ipAddr.IP.IsLoopback() {
				continue
			}
			isIPv4 := ipAddr.IP.To4() != nil
			if ipv4Only && !isIPv4 {
				continue
			}
			if ipv6Only && isIPv4 {
				continue
			}
			filteredSystemIPs = append(filteredSystemIPs, ipAddr)
		}
		if len(filteredSystemIPs) > 0 {
			// Convert []IPAddr to []net.IP
			resultIPs := make([]net.IP, len(filteredSystemIPs))
			for i, ipa := range filteredSystemIPs {
				resultIPs[i] = ipa.IP
			}
			return resultIPs, nil // System resolver succeeded
		}
		// If system resolver returned IPs but none matched the filter or were usable
		err = fmt.Errorf("system resolver returned IPs, but none matched filter or were usable (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
	}
	// Handle errors from LookupIPAddr or the case where no IPs were returned
	if err != nil {
		log.Printf("Debug: System DNS resolution failed for %s: %v\n", host, err)
		sysDNSErr := fmt.Errorf("system DNS failed: %w", err)
		// Ensure lastErr is chained correctly
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, sysDNSErr)
		} else {
			lastErr = sysDNSErr
		}
	} else if len(ipAddrs) == 0 {
		sysDNSErr := errors.New("system DNS failed: no IPs returned")
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, sysDNSErr)
		} else {
			lastErr = sysDNSErr
		}
	}

	// Attempt 3: Direct DNS
	ips, err = resolveWithDirectDNS(ctx, host, ipv4Only, ipv6Only)
	if err == nil && len(ips) > 0 {
		return ips, nil // Direct DNS succeeded
	}
	if err != nil {
		log.Printf("Debug: Direct DNS resolution failed for %s: %v\n", host, err)
		directDNSErr := fmt.Errorf("direct DNS failed: %w", err)
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, directDNSErr)
		} else {
			lastErr = directDNSErr
		}
	} else if len(ips) == 0 { // err == nil but no IPs
		directDNSErr := fmt.Errorf("direct DNS failed: no matching IPs found (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, directDNSErr)
		} else {
			lastErr = directDNSErr
		}
	}

	// All methods failed
	// Ensure we return an error if lastErr is somehow still nil
	if lastErr == nil {
		lastErr = errors.New("all resolution methods failed")
	}
	return nil, fmt.Errorf("all resolution methods failed for %s: %w", host, lastErr)
}

// resolveWithDoH tries to resolve using DNS over HTTPS.
func resolveWithDoH(ctx context.Context, host string, ipv4Only, ipv6Only bool, insecureSkipVerify bool, rootCAs *x509.CertPool) ([]net.IP, error) { // Added rootCAs param
	dohServers := []struct {
		address string // e.g., "1.1.1.1:443" or "[ipv6]:443"
		sni     string // e.g., "cloudflare-dns.com"
		isV4    bool
	}{
		// IPv4
		{"1.1.1.1:443", "cloudflare-dns.com", true},
		{"1.0.0.1:443", "cloudflare-dns.com", true},
		{"8.8.8.8:443", "dns.google", true},
		{"8.8.4.4:443", "dns.google", true},
		{"9.9.9.9:443", "dns.quad9.net", true},
		// IPv6 - *FIXED: Added brackets*
		{"[2606:4700:4700::1111]:443", "cloudflare-dns.com", false},
		{"[2606:4700:4700::1001]:443", "cloudflare-dns.com", false},
		{"[2001:4860:4860::8888]:443", "dns.google", false},
		{"[2001:4860:4860::8844]:443", "dns.google", false},
		{"[2620:fe::fe]:443", "dns.quad9.net", false},
	}

	// Shuffle servers to distribute load and avoid hitting the same failing one first
	rand.Shuffle(len(dohServers), func(i, j int) {
		dohServers[i], dohServers[j] = dohServers[j], dohServers[i]
	})

	// rootCAs pool is now passed in

	var ips []net.IP
	var queryTypes []uint16

	switch {
	case ipv4Only:
		queryTypes = []uint16{dns.TypeA}
	case ipv6Only:
		queryTypes = []uint16{dns.TypeAAAA}
	default:
		queryTypes = []uint16{dns.TypeA, dns.TypeAAAA} // Query both A and AAAA by default
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
			currentErr := fmt.Errorf("failed to pack DNS query type %s: %w", dns.TypeToString[qtype], err)
			if lastErr != nil {
				lastErr = fmt.Errorf("%w; %w", lastErr, currentErr) // Chain errors
			} else {
				lastErr = currentErr
			}
			mu.Unlock()
			continue // Try next query type if packing fails
		}
		b64 := base64.RawURLEncoding.EncodeToString(msg)

		// Try multiple DoH servers concurrently for the same query type
		queryCtx, queryCancel := context.WithCancel(ctx) // Context to cancel other servers once one succeeds for this qtype

		typeAttempted := false // Track if any goroutine was launched for this type

		for _, server := range dohServers {
			// Skip server if its IP version doesn't match the forced flag, if any.
			if (ipv4Only && !server.isV4) || (ipv6Only && server.isV4) {
				continue
			}

			typeAttempted = true
			wg.Add(1)
			go func(server struct {
				address, sni string
				isV4         bool
			}, currentQType uint16) { // Pass currentQType explicitly
				defer wg.Done()
				select {
				case <-queryCtx.Done(): // Check if another goroutine succeeded for this qtype
					return
				default:
				}

				// Create a temporary, short-lived client *per attempt* for DoH request
				dialer := &net.Dialer{Timeout: 3 * time.Second}
				dohTransport := &http.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         server.sni,
						RootCAs:            rootCAs,            // Use the passed-in pool
						InsecureSkipVerify: insecureSkipVerify, // Apply flag here too
					},
					Proxy: http.ProxyFromEnvironment, // Respect proxy for DoH too
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						dohNet := "tcp4"
						if !server.isV4 {
							dohNet = "tcp6"
						}
						// Use a context with timeout for the dial itself
						dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
						defer dialCancel()
						// server.address should now be correctly formatted (e.g., "[::1]:443")
						return dialer.DialContext(dialCtx, dohNet, server.address)
					},
					DisableKeepAlives:     true, // DoH requests are typically single-use
					ForceAttemptHTTP2:     true, // Try HTTP/2
					TLSHandshakeTimeout:   3 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				}
				dohClient := &http.Client{
					Transport: dohTransport,
					Timeout:   5 * time.Second, // Overall timeout for the DoH request
				}
				// Create a request context with timeout derived from the query context
				reqCtx, reqCancel := context.WithTimeout(queryCtx, 5*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, "GET", fmt.Sprintf("https://%s/dns-query?dns=%s", server.sni, b64), nil)
				if err != nil {
					mu.Lock()
					// Check if context was already cancelled (e.g., another goroutine succeeded)
					if !errors.Is(reqCtx.Err(), context.Canceled) {
						currentErr := fmt.Errorf("failed creating DoH request to %s (%s): %w", server.sni, server.address, err)
						if lastErr != nil {
							lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
						} else {
							lastErr = currentErr
						}
					}
					mu.Unlock()
					return
				}
				req.Header.Set("Accept", "application/dns-message")
				resp, err := dohClient.Do(req)
				if err != nil {
					mu.Lock()
					if !errors.Is(reqCtx.Err(), context.Canceled) {
						errStr := fmt.Sprintf("DoH request to %s (%s) failed: %v", server.sni, server.address, err)
						if errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "context deadline exceeded") {
							errStr += " (timeout)"
						}
						// Add hint for certificate errors
						var certErr *x509.UnknownAuthorityError
						if errors.As(err, &certErr) || strings.Contains(err.Error(), "certificate signed by unknown authority") {
							errStr += " (certificate verification failed)"
						}
						currentErr := errors.New(errStr) // Use errors.New for simple string
						if lastErr != nil {
							lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
						} else {
							lastErr = currentErr
						}
					}
					mu.Unlock()
					return
				}
				defer resp.Body.Close() // Ensure body is closed

				if resp.StatusCode != http.StatusOK {
					mu.Lock()
					if !errors.Is(reqCtx.Err(), context.Canceled) {
						// Read body for potential error details, but limit size
						bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
						currentErr := fmt.Errorf("DoH request to %s (%s) returned status %d [%s]", server.sni, server.address, resp.StatusCode, string(bodyBytes))
						if lastErr != nil {
							lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
						} else {
							lastErr = currentErr
						}
					}
					mu.Unlock()
					return
				}
				body, readErr := io.ReadAll(resp.Body)
				if readErr != nil {
					mu.Lock()
					if !errors.Is(reqCtx.Err(), context.Canceled) {
						currentErr := fmt.Errorf("failed reading DoH response body from %s (%s): %w", server.sni, server.address, readErr)
						if lastErr != nil {
							lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
						} else {
							lastErr = currentErr
						}
					}
					mu.Unlock()
					return
				}
				response := new(dns.Msg)
				if err := response.Unpack(body); err != nil {
					mu.Lock()
					if !errors.Is(reqCtx.Err(), context.Canceled) {
						currentErr := fmt.Errorf("failed unpacking DoH response from %s (%s): %w", server.sni, server.address, err)
						if lastErr != nil {
							lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
						} else {
							lastErr = currentErr
						}
					}
					mu.Unlock()
					return
				}

				// Process answers
				mu.Lock()
				// Check if context was cancelled *before* modifying shared state
				if errors.Is(queryCtx.Err(), context.Canceled) {
					mu.Unlock()
					return
				}
				addedRelevantIP := false
				for _, ans := range response.Answer {
					switch a := ans.(type) {
					case *dns.A:
						// Add A if IPv6 is not exclusively requested AND this query was for A records
						if !ipv6Only && currentQType == dns.TypeA && !a.A.IsUnspecified() && !a.A.IsLoopback() {
							ips = append(ips, a.A)
							addedRelevantIP = true
						}
					case *dns.AAAA:
						// Add AAAA if IPv4 is not exclusively requested AND this query was for AAAA records
						if !ipv4Only && currentQType == dns.TypeAAAA && !a.AAAA.IsUnspecified() && !a.AAAA.IsLoopback() {
							ips = append(ips, a.AAAA)
							addedRelevantIP = true
						}
					}
				}

				// If we successfully added IPs of the type we were looking for, mark type as processed and cancel others
				if addedRelevantIP && !processedQueryType[currentQType] {
					processedQueryType[currentQType] = true
					queryCancel() // Cancel other goroutines for this query type
				}
				mu.Unlock()
			}(server, qtype) // Pass server info by value and qtype
		} // End loop through DoH servers for a specific query type

		// Correct placement for queryCancel: Cancel after waiting for this type's goroutines
		// Only wait if goroutines were actually launched for this type
		if typeAttempted {
			wg.Wait()
		}
		queryCancel() // Cancel context after waiting or if no attempts were made

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
			// If both were allowed (default), and we have found at least one IP,
			// we can potentially stop early if we have *both* types.
			if !ipv4Only && !ipv6Only && hasIPv4 && hasIPv6 {
				// Consider breaking here if having both is sufficient
				// mu.Unlock()
				// break
			}
		}
		mu.Unlock()

	} // End of query type loop

	mu.Lock()
	defer mu.Unlock()
	if len(ips) > 0 {
		// Filter final list one more time based on flags, remove unspecified/loopback and duplicates
		filteredIPs := ips[:0]
		uniqueIPs := make(map[string]struct{}) // Avoid duplicates
		for _, ip := range ips {
			ipStr := ip.String()
			if _, exists := uniqueIPs[ipStr]; exists {
				continue
			}
			// Ensure IP is not unspecified or loopback
			if ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			isIPv4 := ip.To4() != nil
			// Apply strict filtering based on flags
			if (ipv4Only && !isIPv4) || (ipv6Only && isIPv4) {
				continue
			}
			filteredIPs = append(filteredIPs, ip)
			uniqueIPs[ipStr] = struct{}{}
		}
		if len(filteredIPs) > 0 {
			return filteredIPs, nil
		}
		// If filtering removed all IPs, create or append error
		currentErr := fmt.Errorf("doH returned IPs, but none matched filter or were usable (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
		} else {
			lastErr = currentErr
		}
	}

	// If no IPs found or all were filtered out
	baseErrMsg := fmt.Sprintf("doH attempts failed for %s", host)
	if lastErr != nil {
		// SA4006/SA4017 Fix: Directly use baseErrMsg in the final fmt.Errorf
		return nil, fmt.Errorf("%s: %w", baseErrMsg, lastErr)
	}

	// This path should ideally not be reached if logic is correct, but handle defensively
	// SA4006/SA4017 Fix: Directly use baseErrMsg and create a new error for lastErr
	lastErr = errors.New("no usable IPs resolved via DoH")
	return nil, fmt.Errorf("%s: %w", baseErrMsg, lastErr)
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
		{"[2606:4700:4700::1111]:53", false}, // Format is correct for miekg/dns
		{"[2606:4700:4700::1001]:53", false}, // Format is correct for miekg/dns
		// Google
		{"8.8.8.8:53", true},
		{"8.8.4.4:53", true},
		{"[2001:4860:4860::8888]:53", false}, // Format is correct for miekg/dns
		{"[2001:4860:4860::8844]:53", false}, // Format is correct for miekg/dns
		// Quad9
		{"9.9.9.9:53", true},
		{"[2620:fe::fe]:53", false}, // Format is correct for miekg/dns
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
	// Use slightly longer timeouts for direct DNS as it might traverse more hops
	dnsClientUDP := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	dnsClientTCP := &dns.Client{Net: "tcp", Timeout: 4 * time.Second}

	for _, qtype := range queryTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		m.RecursionDesired = true
		m.SetEdns0(4096, true) // Request EDNS for larger UDP responses

		queryCtx, queryCancel := context.WithCancel(ctx) // Context for this query type

		typeAttempted := false // Track if any goroutine was launched for this type

		for _, server := range servers {
			// Skip server if its IP version doesn't match the forced flag
			if (ipv4Only && !server.isV4) || (ipv6Only && server.isV4) {
				continue
			}

			typeAttempted = true
			wg.Add(1)
			go func(serverAddr string, currentQType uint16) { // Pass qtype explicitly
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

				// Create a context for the UDP attempt derived from queryCtx
				udpCtx, udpCancel := context.WithTimeout(queryCtx, dnsClientUDP.Timeout)
				defer udpCancel() // Ensure cancellation

				// Try UDP first
				response, rtt, err = dnsClientUDP.ExchangeContext(udpCtx, m, serverAddr)

				// Check conditions for TCP retry: network error, timeout, or truncated response
				needsTCPRetry := false
				if err != nil {
					// Retry on timeout or if the context specific to UDP expired
					// Do not retry if the parent context (queryCtx) was cancelled
					if !errors.Is(queryCtx.Err(), context.Canceled) && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)) {
						needsTCPRetry = true
					}
				} else if response != nil && response.Truncated {
					needsTCPRetry = true
				}

				// Retry with TCP if needed and not already successful (and not cancelled)
				var tcpCtx context.Context // Declare tcpCtx here
				var tcpCancel context.CancelFunc
				if needsTCPRetry && !errors.Is(queryCtx.Err(), context.Canceled) && (response == nil || response.Rcode != dns.RcodeSuccess) {
					attemptedTCP = true
					// Create a context for the TCP attempt
					tcpCtx, tcpCancel = context.WithTimeout(queryCtx, dnsClientTCP.Timeout) // Assign to declared variables
					defer tcpCancel()
					response, rtt, err = dnsClientTCP.ExchangeContext(tcpCtx, m, serverAddr)
					// Check for parent cancellation again after TCP attempt
					if errors.Is(queryCtx.Err(), context.Canceled) {
						return // Stop processing if cancelled during TCP attempt
					}
				}

				// --- Process the final result (either UDP or TCP) ---
				mu.Lock() // Lock before checking errors or processing results
				// Check for cancellation *before* processing error/result
				if errors.Is(queryCtx.Err(), context.Canceled) {
					mu.Unlock()
					return
				}

				if err != nil || (response != nil && response.Rcode != dns.RcodeSuccess) {
					protocol := "UDP"
					if attemptedTCP {
						protocol = "TCP"
					}
					errStr := fmt.Sprintf("direct DNS %s query to %s for %s failed: %v", protocol, serverAddr, dns.TypeToString[currentQType], err)
					if response != nil && response.Rcode != dns.RcodeSuccess {
						errStr += fmt.Sprintf(" (RCODE: %s)", dns.RcodeToString[response.Rcode])
					}
					// Check specific context errors for timeout hints
					// FIX: Check queryCtx.Err() instead of ctx directly. Also check tcpCtx.Err() if attemptedTCP.
					if errors.Is(err, context.DeadlineExceeded) || errors.Is(udpCtx.Err(), context.DeadlineExceeded) || (attemptedTCP && tcpCtx != nil && errors.Is(tcpCtx.Err(), context.DeadlineExceeded)) || errors.Is(queryCtx.Err(), context.DeadlineExceeded) {
						errStr += " (timeout)"
					}

					currentErr := errors.New(errStr) // Use errors.New for simple string
					if lastErr != nil {
						lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
					} else {
						lastErr = currentErr
					}
					mu.Unlock()
					return // Query failed
				}

				// Process successful response
				_ = rtt // RTT not used currently
				addedRelevantIP := false
				for _, ans := range response.Answer {
					switch a := ans.(type) {
					case *dns.A:
						// Add A if IPv6 is not exclusively requested AND this query was for A records
						if !ipv6Only && currentQType == dns.TypeA && !a.A.IsUnspecified() && !a.A.IsLoopback() {
							ips = append(ips, a.A)
							addedRelevantIP = true
						}
					case *dns.AAAA:
						// Add AAAA if IPv4 is not exclusively requested AND this query was for AAAA records
						if !ipv4Only && currentQType == dns.TypeAAAA && !a.AAAA.IsUnspecified() && !a.AAAA.IsLoopback() {
							ips = append(ips, a.AAAA)
							addedRelevantIP = true
						}
					}
				}

				if addedRelevantIP && !processedQueryType[currentQType] {
					processedQueryType[currentQType] = true
					queryCancel() // Cancel others for this query type
				}
				mu.Unlock()

			}(server.addr, qtype) // Pass server address and qtype by value
		} // End loop through direct DNS servers

		// Correct placement for queryCancel
		if typeAttempted {
			wg.Wait() // Wait for all direct DNS attempts for this qtype
		}
		queryCancel() // Cancel context after waiting or if no attempts made

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
			// Stop early if the required IP family has been found
			if (ipv4Only && hasIPv4) || (ipv6Only && hasIPv6) {
				mu.Unlock()
				break // Stop querying other types
			}
			// If both allowed and we have both, consider stopping
			if !ipv4Only && !ipv6Only && hasIPv4 && hasIPv6 {
				// mu.Unlock() // Potentially break early
				// break
			}
		}
		mu.Unlock()
	} // End query type loop

	mu.Lock()
	defer mu.Unlock()

	if len(ips) > 0 {
		// Filter final list one more time based on flags, remove unspecified/loopback and duplicates
		filteredIPs := ips[:0]
		uniqueIPs := make(map[string]struct{})
		for _, ip := range ips {
			ipStr := ip.String()
			if _, exists := uniqueIPs[ipStr]; exists {
				continue
			}
			// Ensure IP is not unspecified or loopback
			if ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			isIPv4 := ip.To4() != nil
			// Apply strict filtering
			if (ipv4Only && !isIPv4) || (ipv6Only && isIPv4) {
				continue
			}
			filteredIPs = append(filteredIPs, ip)
			uniqueIPs[ipStr] = struct{}{}
		}
		if len(filteredIPs) > 0 {
			return filteredIPs, nil
		}
		// If filtering removed all IPs, create or append error
		currentErr := fmt.Errorf("direct DNS returned IPs, but none matched filter or were usable (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
		} else {
			lastErr = currentErr
		}
	}

	// If no IPs found or all filtered
	baseErrMsg := fmt.Sprintf("direct DNS attempts failed for %s", host)
	if lastErr != nil {
		// SA4006/SA4017 Fix: Directly use baseErrMsg in the final fmt.Errorf
		return nil, fmt.Errorf("%s: %w", baseErrMsg, lastErr)
	}

	// This path should ideally not be reached if logic is correct, but handle defensively
	// SA4006/SA4017 Fix: Directly use baseErrMsg and create a new error for lastErr
	lastErr = errors.New("no usable IPs resolved via direct DNS")
	return nil, fmt.Errorf("%s: %w", baseErrMsg, lastErr)
}

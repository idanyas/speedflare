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

	if selectedIP == nil {
		family := "any"
		if ipv4Only {
			family = "IPv4"
		} else if ipv6Only {
			family = "IPv6"
		}
		return nil, fmt.Errorf("no suitable %s IP address found for interface %q", family, interfaceOrIP)
	}

	return &net.TCPAddr{IP: selectedIP, Port: 0}, nil
}

// NewHTTPClient creates a new HTTP client with options for IP version, interface binding, and TLS verification skipping.
func NewHTTPClient(ipv4OnlyFlag, ipv6OnlyFlag bool, interfaceOrIP string, insecureSkipVerify bool) (*http.Client, error) {
	localAddr, err := getLocalAddr(interfaceOrIP, ipv4OnlyFlag, ipv6OnlyFlag)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: localAddr,
	}

	// Prepare base TLS config
	tlsClientConfig := &tls.Config{
		ServerName:         "speed.cloudflare.com", // Default SNI for the main client's transport
		InsecureSkipVerify: insecureSkipVerify,
	}

	if !insecureSkipVerify {
		// Use rootcerts.ServerCertPool() which attempts to load system CAs
		// and appends its own embedded Mozilla CA bundle. If system CAs
		// fail to load, it returns a pool with only the embedded CAs.
		tlsClientConfig.RootCAs = rootcerts.ServerCertPool()

		// As a final safeguard, if tlsClientConfig.RootCAs is still somehow nil
		// (which shouldn't happen with a functional rootcerts.ServerCertPool()),
		// explicitly log and set it.
		if tlsClientConfig.RootCAs == nil {
			log.Println("Warning: rootcerts.ServerCertPool() returned nil. This indicates a problem with root certificate loading. Forcing embedded certs again.")
			// Attempting again or panicking might be options, but for now, re-assigning is a simple fallback.
			tlsClientConfig.RootCAs = rootcerts.ServerCertPool()
			if tlsClientConfig.RootCAs == nil {
				// This would be a critical failure of the rootcerts library or environment.
				return nil, errors.New("critical failure: unable to obtain a valid root CA pool")
			}
		}
	}
	// If insecureSkipVerify is true, tlsClientConfig.RootCAs remains nil (or whatever it was, usually nil),
	// and InsecureSkipVerify=true takes precedence in TLS handshake, which is correct.

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// These flags are local to DialContext, initially taking values from NewHTTPClient's parameters.
			// They might be modified if LocalAddr forces a specific IP family.
			currentIpv4Only := ipv4OnlyFlag
			currentIpv6Only := ipv6OnlyFlag

			networkPreference := "tcp"
			if currentIpv4Only {
				networkPreference = "tcp4"
			} else if currentIpv6Only {
				networkPreference = "tcp6"
			}

			if tcpAddr, ok := dialer.LocalAddr.(*net.TCPAddr); ok && tcpAddr.IP != nil {
				if tcpAddr.IP.To4() != nil {
					if currentIpv6Only {
						return nil, fmt.Errorf("cannot bind to IPv4 address %s when --ipv6 is specified", tcpAddr.IP.String())
					}
					networkPreference = "tcp4"
					currentIpv4Only = true
					currentIpv6Only = false
				} else {
					if currentIpv4Only {
						return nil, fmt.Errorf("cannot bind to IPv6 address %s when --ipv4 is specified", tcpAddr.IP.String())
					}
					networkPreference = "tcp6"
					currentIpv6Only = true
					currentIpv4Only = false
				}
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("invalid address format: %w", err)
			}

			if ip := net.ParseIP(host); ip != nil {
				isIPv4 := ip.To4() != nil
				currentNetworkType := "tcp6"
				if isIPv4 {
					currentNetworkType = "tcp4"
				}

				if (networkPreference == "tcp4" && !isIPv4) || (networkPreference == "tcp6" && isIPv4) {
					return nil, fmt.Errorf("target IP address %s does not match required network type %s", host, networkPreference)
				}
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

			// Resolve hostname using the multi-stage resolver.
			// Pass the RootCAs pool from the prepared tlsClientConfig.
			// Also pass currentIpv4Only/currentIpv6Only which reflect any LocalAddr constraints.
			resolvedIPs, resolveErr := resolveHost(ctx, host, currentIpv4Only, currentIpv6Only, insecureSkipVerify, tlsClientConfig.RootCAs)
			if resolveErr != nil {
				return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, resolveErr)
			}
			if len(resolvedIPs) == 0 {
				return nil, fmt.Errorf("DNS resolution failed: no usable IPs returned for %s (ipv4=%v, ipv6=%v)", host, currentIpv4Only, currentIpv6Only)
			}

			var firstDialErr error
			for _, ip := range resolvedIPs {
				ipStr := ip.String()
				isIPv4 := ip.To4() != nil

				currentNetworkType := "tcp"
				if isIPv4 {
					currentNetworkType = "tcp4"
				} else {
					currentNetworkType = "tcp6"
				}

				if (networkPreference == "tcp4" && !isIPv4) || (networkPreference == "tcp6" && isIPv4) {
					// log.Printf("Debug: Skipping resolved IP %s as it doesn't match required family %s\n", ipStr, networkPreference)
					continue
				}

				conn, dialErr := dialer.DialContext(ctx, currentNetworkType, net.JoinHostPort(ipStr, port))
				if dialErr == nil {
					return conn, nil // Success
				}
				if firstDialErr == nil {
					firstDialErr = dialErr
				}
			}

			errMsg := fmt.Sprintf("connection failed to all resolved IPs for %s:%s", host, port)
			if firstDialErr != nil {
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
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsClientConfig, // Use the prepared tlsClientConfig for the main transport
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}, nil
}

// resolveHost attempts to resolve a hostname using DoH, then system DNS, then direct DNS queries.
// It receives the rootCAs pool to be used for DoH TLS verification.
func resolveHost(ctx context.Context, host string, ipv4Only, ipv6Only bool, insecureSkipVerify bool, rootCAs *x509.CertPool) ([]net.IP, error) {
	var lastErr error
	var ips []net.IP

	// Attempt 1: DoH
	ips, err := resolveWithDoH(ctx, host, ipv4Only, ipv6Only, insecureSkipVerify, rootCAs)
	if err == nil && len(ips) > 0 {
		return ips, nil
	}
	if err != nil {
		log.Printf("Debug: DoH resolution failed for %s: %v\n", host, err)
		lastErr = fmt.Errorf("doH failed: %w", err)
	} else {
		lastErr = fmt.Errorf("doH failed: no matching IPs found (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
	}

	// Attempt 2: System Resolver
	resolver := net.Resolver{}
	ipAddrs, err := resolver.LookupIPAddr(ctx, host)
	if err == nil && len(ipAddrs) > 0 {
		filteredSystemIPs := ipAddrs[:0]
		for _, ipAddr := range ipAddrs {
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
			resultIPs := make([]net.IP, len(filteredSystemIPs))
			for i, ipa := range filteredSystemIPs {
				resultIPs[i] = ipa.IP
			}
			return resultIPs, nil
		}
		err = fmt.Errorf("system resolver returned IPs, but none matched filter or were usable (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
	}
	if err != nil {
		log.Printf("Debug: System DNS resolution failed for %s: %v\n", host, err)
		sysDNSErr := fmt.Errorf("system DNS failed: %w", err)
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
		return ips, nil
	}
	if err != nil {
		log.Printf("Debug: Direct DNS resolution failed for %s: %v\n", host, err)
		directDNSErr := fmt.Errorf("direct DNS failed: %w", err)
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, directDNSErr)
		} else {
			lastErr = directDNSErr
		}
	} else if len(ips) == 0 {
		directDNSErr := fmt.Errorf("direct DNS failed: no matching IPs found (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, directDNSErr)
		} else {
			lastErr = directDNSErr
		}
	}

	if lastErr == nil {
		lastErr = errors.New("all resolution methods failed")
	}
	return nil, fmt.Errorf("all resolution methods failed for %s: %w", host, lastErr)
}

// resolveWithDoH tries to resolve using DNS over HTTPS.
// It receives the rootCAs pool (system+embedded or nil if insecure) for TLS verification.
func resolveWithDoH(ctx context.Context, host string, ipv4Only, ipv6Only bool, insecureSkipVerify bool, rootCAs *x509.CertPool) ([]net.IP, error) {
	dohServers := []struct {
		address string
		sni     string
		isV4    bool
	}{
		{"1.1.1.1:443", "cloudflare-dns.com", true},
		{"1.0.0.1:443", "cloudflare-dns.com", true},
		{"8.8.8.8:443", "dns.google", true},
		{"8.8.4.4:443", "dns.google", true},
		{"9.9.9.9:443", "dns.quad9.net", true},
		{"[2606:4700:4700::1111]:443", "cloudflare-dns.com", false},
		{"[2606:4700:4700::1001]:443", "cloudflare-dns.com", false},
		{"[2001:4860:4860::8888]:443", "dns.google", false},
		{"[2001:4860:4860::8844]:443", "dns.google", false},
		{"[2620:fe::fe]:443", "dns.quad9.net", false},
	}

	rand.Shuffle(len(dohServers), func(i, j int) {
		dohServers[i], dohServers[j] = dohServers[j], dohServers[i]
	})

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
	var mu sync.Mutex
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
				lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
			} else {
				lastErr = currentErr
			}
			mu.Unlock()
			continue
		}
		b64 := base64.RawURLEncoding.EncodeToString(msg)

		queryCtx, queryCancel := context.WithCancel(ctx)
		typeAttempted := false

		for _, server := range dohServers {
			if (ipv4Only && !server.isV4) || (ipv6Only && server.isV4) {
				continue
			}

			typeAttempted = true
			wg.Add(1)
			go func(server struct {
				address, sni string
				isV4         bool
			}, currentQType uint16) {
				defer wg.Done()
				select {
				case <-queryCtx.Done():
					return
				default:
				}

				dialer := &net.Dialer{Timeout: 3 * time.Second}
				dohTransport := &http.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         server.sni,
						RootCAs:            rootCAs, // Use the passed-in (potentially augmented) pool
						InsecureSkipVerify: insecureSkipVerify,
					},
					Proxy: http.ProxyFromEnvironment,
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						dohNet := "tcp4"
						if !server.isV4 {
							dohNet = "tcp6"
						}
						dialCtx, dialCancel := context.WithTimeout(ctx, 3*time.Second)
						defer dialCancel()
						return dialer.DialContext(dialCtx, dohNet, server.address)
					},
					DisableKeepAlives:     true,
					ForceAttemptHTTP2:     true,
					TLSHandshakeTimeout:   3 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				}
				dohClient := &http.Client{
					Transport: dohTransport,
					Timeout:   5 * time.Second,
				}
				reqCtx, reqCancel := context.WithTimeout(queryCtx, 5*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, "GET", fmt.Sprintf("https://%s/dns-query?dns=%s", server.sni, b64), nil)
				if err != nil {
					mu.Lock()
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
						var certErr *x509.UnknownAuthorityError
						if errors.As(err, &certErr) || strings.Contains(err.Error(), "certificate signed by unknown authority") {
							errStr += " (certificate verification failed)"
						}
						currentErr := errors.New(errStr)
						if lastErr != nil {
							lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
						} else {
							lastErr = currentErr
						}
					}
					mu.Unlock()
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					mu.Lock()
					if !errors.Is(reqCtx.Err(), context.Canceled) {
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

				mu.Lock()
				if errors.Is(queryCtx.Err(), context.Canceled) {
					mu.Unlock()
					return
				}
				addedRelevantIP := false
				for _, ans := range response.Answer {
					switch a := ans.(type) {
					case *dns.A:
						if !ipv6Only && currentQType == dns.TypeA && !a.A.IsUnspecified() && !a.A.IsLoopback() {
							ips = append(ips, a.A)
							addedRelevantIP = true
						}
					case *dns.AAAA:
						if !ipv4Only && currentQType == dns.TypeAAAA && !a.AAAA.IsUnspecified() && !a.AAAA.IsLoopback() {
							ips = append(ips, a.AAAA)
							addedRelevantIP = true
						}
					}
				}

				if addedRelevantIP && !processedQueryType[currentQType] {
					processedQueryType[currentQType] = true
					queryCancel()
				}
				mu.Unlock()
			}(server, qtype)
		}

		if typeAttempted {
			wg.Wait()
		}
		queryCancel()

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
				break
			}
			if !ipv4Only && !ipv6Only && hasIPv4 && hasIPv6 {
				// mu.Unlock() // Optional: break if both found and both allowed
				// break
			}
		}
		mu.Unlock()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(ips) > 0 {
		filteredIPs := ips[:0]
		uniqueIPs := make(map[string]struct{})
		for _, ip := range ips {
			ipStr := ip.String()
			if _, exists := uniqueIPs[ipStr]; exists {
				continue
			}
			if ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			isIPv4 := ip.To4() != nil
			if (ipv4Only && !isIPv4) || (ipv6Only && isIPv4) {
				continue
			}
			filteredIPs = append(filteredIPs, ip)
			uniqueIPs[ipStr] = struct{}{}
		}
		if len(filteredIPs) > 0 {
			return filteredIPs, nil
		}
		currentErr := fmt.Errorf("doH returned IPs, but none matched filter or were usable (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
		} else {
			lastErr = currentErr
		}
	}

	baseErrMsg := fmt.Sprintf("doH attempts failed for %s", host)
	if lastErr != nil {
		return nil, fmt.Errorf("%s: %w", baseErrMsg, lastErr)
	}
	lastErr = errors.New("no usable IPs resolved via DoH")
	return nil, fmt.Errorf("%s: %w", baseErrMsg, lastErr)
}

// resolveWithDirectDNS attempts to resolve using standard DNS queries to public resolvers.
func resolveWithDirectDNS(ctx context.Context, host string, ipv4Only, ipv6Only bool) ([]net.IP, error) {
	servers := []struct {
		addr string
		isV4 bool
	}{
		{"1.1.1.1:53", true},
		{"1.0.0.1:53", true},
		{"[2606:4700:4700::1111]:53", false},
		{"[2606:4700:4700::1001]:53", false},
		{"8.8.8.8:53", true},
		{"8.8.4.4:53", true},
		{"[2001:4860:4860::8888]:53", false},
		{"[2001:4860:4860::8844]:53", false},
		{"9.9.9.9:53", true},
		{"[2620:fe::fe]:53", false},
	}

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
	var mu sync.Mutex
	processedQueryType := make(map[uint16]bool)

	dnsClientUDP := &dns.Client{Net: "udp", Timeout: 3 * time.Second}
	dnsClientTCP := &dns.Client{Net: "tcp", Timeout: 4 * time.Second}

	for _, qtype := range queryTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		m.RecursionDesired = true
		m.SetEdns0(4096, true)

		queryCtx, queryCancel := context.WithCancel(ctx)
		typeAttempted := false

		for _, server := range servers {
			if (ipv4Only && !server.isV4) || (ipv6Only && server.isV4) {
				continue
			}

			typeAttempted = true
			wg.Add(1)
			go func(serverAddr string, currentQType uint16) {
				defer wg.Done()
				select {
				case <-queryCtx.Done():
					return
				default:
				}

				var response *dns.Msg
				var err error
				var rtt time.Duration
				attemptedTCP := false

				udpCtx, udpCancel := context.WithTimeout(queryCtx, dnsClientUDP.Timeout)
				response, rtt, err = dnsClientUDP.ExchangeContext(udpCtx, m, serverAddr)
				udpCancel() // Release resources associated with udpCtx

				needsTCPRetry := false
				if err != nil {
					if !errors.Is(queryCtx.Err(), context.Canceled) && (errors.Is(err, context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded)) {
						needsTCPRetry = true
					}
				} else if response != nil && response.Truncated {
					needsTCPRetry = true
				}

				var tcpCtx context.Context
				var tcpCancel context.CancelFunc
				if needsTCPRetry && !errors.Is(queryCtx.Err(), context.Canceled) && (response == nil || response.Rcode != dns.RcodeSuccess) {
					attemptedTCP = true
					tcpCtx, tcpCancel = context.WithTimeout(queryCtx, dnsClientTCP.Timeout)
					response, rtt, err = dnsClientTCP.ExchangeContext(tcpCtx, m, serverAddr)
					if tcpCancel != nil { // tcpCancel is nil if context wasn't created
						tcpCancel() // Release resources associated with tcpCtx
					}
					if errors.Is(queryCtx.Err(), context.Canceled) {
						return
					}
				}

				mu.Lock()
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

					// Check various contexts for timeout
					timeoutOccurred := errors.Is(err, context.DeadlineExceeded) ||
						(udpCtx != nil && errors.Is(udpCtx.Err(), context.DeadlineExceeded)) || // Check original UDP context
						(attemptedTCP && tcpCtx != nil && errors.Is(tcpCtx.Err(), context.DeadlineExceeded)) || // Check TCP context
						errors.Is(queryCtx.Err(), context.DeadlineExceeded) // Check overall query type context

					if timeoutOccurred {
						errStr += " (timeout)"
					}

					currentErr := errors.New(errStr)
					if lastErr != nil {
						lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
					} else {
						lastErr = currentErr
					}
					mu.Unlock()
					return
				}

				_ = rtt
				addedRelevantIP := false
				for _, ans := range response.Answer {
					switch a := ans.(type) {
					case *dns.A:
						if !ipv6Only && currentQType == dns.TypeA && !a.A.IsUnspecified() && !a.A.IsLoopback() {
							ips = append(ips, a.A)
							addedRelevantIP = true
						}
					case *dns.AAAA:
						if !ipv4Only && currentQType == dns.TypeAAAA && !a.AAAA.IsUnspecified() && !a.AAAA.IsLoopback() {
							ips = append(ips, a.AAAA)
							addedRelevantIP = true
						}
					}
				}

				if addedRelevantIP && !processedQueryType[currentQType] {
					processedQueryType[currentQType] = true
					queryCancel()
				}
				mu.Unlock()

			}(server.addr, qtype)
		}

		if typeAttempted {
			wg.Wait()
		}
		queryCancel()

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
				break
			}
			if !ipv4Only && !ipv6Only && hasIPv4 && hasIPv6 {
				// mu.Unlock()
				// break
			}
		}
		mu.Unlock()
	}

	mu.Lock()
	defer mu.Unlock()

	if len(ips) > 0 {
		filteredIPs := ips[:0]
		uniqueIPs := make(map[string]struct{})
		for _, ip := range ips {
			ipStr := ip.String()
			if _, exists := uniqueIPs[ipStr]; exists {
				continue
			}
			if ip.IsUnspecified() || ip.IsLoopback() {
				continue
			}
			isIPv4 := ip.To4() != nil
			if (ipv4Only && !isIPv4) || (ipv6Only && isIPv4) {
				continue
			}
			filteredIPs = append(filteredIPs, ip)
			uniqueIPs[ipStr] = struct{}{}
		}
		if len(filteredIPs) > 0 {
			return filteredIPs, nil
		}
		currentErr := fmt.Errorf("direct DNS returned IPs, but none matched filter or were usable (ipv4=%v, ipv6=%v)", ipv4Only, ipv6Only)
		if lastErr != nil {
			lastErr = fmt.Errorf("%w; %w", lastErr, currentErr)
		} else {
			lastErr = currentErr
		}
	}

	baseErrMsg := fmt.Sprintf("direct DNS attempts failed for %s", host)
	if lastErr != nil {
		return nil, fmt.Errorf("%s: %w", baseErrMsg, lastErr)
	}
	lastErr = errors.New("no usable IPs resolved via direct DNS")
	return nil, fmt.Errorf("%s: %w", baseErrMsg, lastErr)
}

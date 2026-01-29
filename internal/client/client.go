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
	"sync"
	"time"

	"github.com/gwatts/rootcerts"
	"github.com/miekg/dns"
)

// BrowserTransport wraps an http.RoundTripper and adds browser-mimicking headers.
type BrowserTransport struct {
	Transport *http.Transport
}

func (t *BrowserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())

	if clone.Header.Get("User-Agent") == "" {
		clone.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
	}
	clone.Header.Set("Referer", "https://speed.cloudflare.com/")
	clone.Header.Set("Accept-Language", "en-US,en;q=0.9")
	clone.Header.Set("Accept", "*/*")
	clone.Header.Set("Cache-Control", "no-cache")

	return t.Transport.RoundTrip(clone)
}

func getLocalAddr(interfaceOrIP string, ipv4Only, ipv6Only bool) (net.Addr, error) {
	if interfaceOrIP == "" {
		return nil, nil
	}

	if ip := net.ParseIP(interfaceOrIP); ip != nil {
		isIPv4 := ip.To4() != nil
		if ipv4Only && !isIPv4 {
			return nil, fmt.Errorf("provided IP %s is not IPv4, but --ipv4 flag was specified", interfaceOrIP)
		}
		if ipv6Only && isIPv4 {
			return nil, fmt.Errorf("provided IP %s is not IPv6, but --ipv6 flag was specified", interfaceOrIP)
		}
		return &net.TCPAddr{IP: ip, Port: 0}, nil
	}

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
		if ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		isIPv4 := ip.To4() != nil
		isIPv6 := !isIPv4

		if ipv4Only && isIPv4 {
			selectedIP = ip
			break
		} else if ipv6Only && isIPv6 {
			if !ip.IsLinkLocalUnicast() {
				selectedIP = ip
				break
			} else if selectedIP == nil {
				selectedIP = ip
			}
		} else if !ipv4Only && !ipv6Only {
			if isIPv6 && !ip.IsLinkLocalUnicast() {
				selectedIP = ip
				break
			} else if isIPv4 {
				if selectedIP == nil || (selectedIP.IsLinkLocalUnicast()) {
					selectedIP = ip
				}
			} else if isIPv6 && ip.IsLinkLocalUnicast() && selectedIP == nil {
				selectedIP = ip
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

// NewHTTPClient creates a new HTTP client.
// forcedIP argument allows binding to a specific destination IP (ignoring DNS), used for colo selection.
func NewHTTPClient(ipv4OnlyFlag, ipv6OnlyFlag bool, interfaceOrIP string, insecureSkipVerify bool, forcedIP string) (*http.Client, error) {
	localAddr, err := getLocalAddr(interfaceOrIP, ipv4OnlyFlag, ipv6OnlyFlag)
	if err != nil {
		return nil, err
	}

	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		LocalAddr: localAddr,
	}

	tlsClientConfig := &tls.Config{
		ServerName:         "speed.cloudflare.com",
		InsecureSkipVerify: insecureSkipVerify,
	}

	if !insecureSkipVerify {
		tlsClientConfig.RootCAs = rootcerts.ServerCertPool()
		if tlsClientConfig.RootCAs == nil {
			log.Println("Warning: rootcerts.ServerCertPool() returned nil. Forcing embedded certs again.")
			tlsClientConfig.RootCAs = rootcerts.ServerCertPool()
			if tlsClientConfig.RootCAs == nil {
				return nil, errors.New("critical failure: unable to obtain a valid root CA pool")
			}
		}
	}

	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Forced IP Logic
			if forcedIP != "" {
				_, port, err := net.SplitHostPort(addr)
				if err != nil {
					return nil, fmt.Errorf("invalid address format: %w", err)
				}

				targetIP := net.ParseIP(forcedIP)
				if targetIP == nil {
					return nil, fmt.Errorf("invalid forced IP: %s", forcedIP)
				}

				// If forcedIP is IPv4, force tcp4. If IPv6, force tcp6.
				networkType := "tcp"
				if targetIP.To4() != nil {
					networkType = "tcp4"
				} else {
					networkType = "tcp6"
				}

				return dialer.DialContext(ctx, networkType, net.JoinHostPort(forcedIP, port))
			}

			// Standard Logic
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
					// Error handling logic
					return nil, dialErr
				}
				return conn, nil
			}

			resolvedIPs, resolveErr := resolveHost(ctx, host, currentIpv4Only, currentIpv6Only, insecureSkipVerify, tlsClientConfig.RootCAs)
			if resolveErr != nil {
				return nil, fmt.Errorf("DNS resolution failed for %s: %w", host, resolveErr)
			}
			if len(resolvedIPs) == 0 {
				return nil, fmt.Errorf("DNS resolution failed: no usable IPs returned for %s", host)
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
					continue
				}

				// Implement per-IP timeout to prevent one blackholed IP from stalling the entire process
				dialCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				conn, dialErr := dialer.DialContext(dialCtx, currentNetworkType, net.JoinHostPort(ipStr, port))
				cancel()

				if dialErr == nil {
					return conn, nil // Success
				}
				if firstDialErr == nil {
					firstDialErr = dialErr
				}
			}

			return nil, fmt.Errorf("connection failed to all resolved IPs for %s:%s (first error: %v)", host, port, firstDialErr)

		},
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		DisableCompression:    true,
		ForceAttemptHTTP2:     true,
		TLSClientConfig:       tlsClientConfig,
	}

	return &http.Client{
		Transport: &BrowserTransport{Transport: transport},
		Timeout:   30 * time.Second,
	}, nil
}

func resolveHost(ctx context.Context, host string, ipv4Only, ipv6Only bool, insecureSkipVerify bool, rootCAs *x509.CertPool) ([]net.IP, error) {
	var lastErr error
	var ips []net.IP

	// Attempt 1: DoH
	ips, err := resolveWithDoH(ctx, host, ipv4Only, ipv6Only, insecureSkipVerify, rootCAs)
	if err == nil && len(ips) > 0 {
		return ips, nil
	}
	if err != nil {
		lastErr = fmt.Errorf("doH failed: %w", err)
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
	}
	if err != nil {
		sysDNSErr := fmt.Errorf("system DNS failed: %w", err)
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
		directDNSErr := fmt.Errorf("direct DNS failed: %w", err)
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

				dialer := &net.Dialer{Timeout: 5 * time.Second}
				dohTransport := &http.Transport{
					TLSClientConfig: &tls.Config{
						ServerName:         server.sni,
						RootCAs:            rootCAs,
						InsecureSkipVerify: insecureSkipVerify,
					},
					Proxy: http.ProxyFromEnvironment,
					DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
						dohNet := "tcp4"
						if !server.isV4 {
							dohNet = "tcp6"
						}
						dialCtx, dialCancel := context.WithTimeout(ctx, 5*time.Second)
						defer dialCancel()
						return dialer.DialContext(dialCtx, dohNet, server.address)
					},
					DisableKeepAlives:     true,
					ForceAttemptHTTP2:     true,
					TLSHandshakeTimeout:   5 * time.Second,
					ExpectContinueTimeout: 1 * time.Second,
				}
				dohClient := &http.Client{
					Transport: dohTransport,
					Timeout:   10 * time.Second,
				}
				reqCtx, reqCancel := context.WithTimeout(queryCtx, 10*time.Second)
				defer reqCancel()
				req, err := http.NewRequestWithContext(reqCtx, "GET", fmt.Sprintf("https://%s/dns-query?dns=%s", server.sni, b64), nil)
				if err != nil {
					mu.Lock()
					if !errors.Is(reqCtx.Err(), context.Canceled) {
						if lastErr == nil {
							lastErr = err
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
						if lastErr == nil {
							lastErr = err
						}
					}
					mu.Unlock()
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					return
				}
				body, _ := io.ReadAll(resp.Body)
				response := new(dns.Msg)
				if err := response.Unpack(body); err != nil {
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

		// If IPs found, break outer loop
		mu.Lock()
		if len(ips) > 0 {
			mu.Unlock()
			break
		}
		mu.Unlock()
	}

	mu.Lock()
	defer mu.Unlock()
	if len(ips) > 0 {
		return ips, nil
	}

	return nil, fmt.Errorf("no usable IPs resolved via DoH")
}

func resolveWithDirectDNS(ctx context.Context, host string, ipv4Only, ipv6Only bool) ([]net.IP, error) {
	servers := []struct {
		addr string
		isV4 bool
	}{
		{"1.1.1.1:53", true},
		{"8.8.8.8:53", true},
		{"9.9.9.9:53", true},
		{"[2606:4700:4700::1111]:53", false},
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
	var wg sync.WaitGroup
	var mu sync.Mutex
	processedQueryType := make(map[uint16]bool)

	dnsClientUDP := &dns.Client{Net: "udp", Timeout: 3 * time.Second}

	for _, qtype := range queryTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), qtype)
		m.RecursionDesired = true

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

				response, _, err := dnsClientUDP.ExchangeContext(queryCtx, m, serverAddr)

				mu.Lock()
				if errors.Is(queryCtx.Err(), context.Canceled) {
					mu.Unlock()
					return
				}

				if err != nil || (response != nil && response.Rcode != dns.RcodeSuccess) {
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

			}(server.addr, qtype)
		}

		if typeAttempted {
			wg.Wait()
		}
		queryCancel()

		mu.Lock()
		if len(ips) > 0 {
			mu.Unlock()
			break
		}
		mu.Unlock()
	}

	mu.Lock()
	defer mu.Unlock()

	if len(ips) > 0 {
		return ips, nil
	}
	return nil, errors.New("no usable IPs resolved via direct DNS")
}

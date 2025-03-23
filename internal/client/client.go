// internal/client/client.go
package client

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/miekg/dns"
)

func NewHTTPClient(ipv4, ipv6 bool) *http.Client {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	transport := &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if ipv4 {
				network = "tcp4"
			} else if ipv6 {
				network = "tcp6"
			}

			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			if ip := net.ParseIP(host); ip != nil {
				return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
			}

			var dnsTypes []uint16
			switch network {
			case "tcp4":
				dnsTypes = []uint16{dns.TypeA}
			case "tcp6":
				dnsTypes = []uint16{dns.TypeAAAA}
			default:
				dnsTypes = []uint16{dns.TypeA, dns.TypeAAAA}
			}

			ips, err := resolveWithDoH(ctx, host, dnsTypes)
			if err != nil {
				return nil, err
			}

			var firstErr error
			for _, ip := range ips {
				if (network == "tcp4" && ip.To4() == nil) || (network == "tcp6" && ip.To4() != nil) {
					continue
				}

				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				if firstErr == nil {
					firstErr = err
				}
			}

			if firstErr != nil {
				return nil, firstErr
			}
			return nil, fmt.Errorf("no IP addresses found for %s", host)
		},
		MaxIdleConns:       100,
		IdleConnTimeout:    90 * time.Second,
		DisableCompression: true,
		ForceAttemptHTTP2:  true,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
}

func resolveWithDoH(ctx context.Context, host string, dnsTypes []uint16) ([]net.IP, error) {
	var ips []net.IP

	for _, dnsType := range dnsTypes {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(host), dnsType)
		m.RecursionDesired = true

		msg, err := m.Pack()
		if err != nil {
			return nil, err
		}

		b64 := base64.RawURLEncoding.EncodeToString(msg)
		url := fmt.Sprintf("https://1.1.1.1/dns-query?dns=%s", b64)

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		req.Host = "cloudflare-dns.com"
		req.Header.Set("Accept", "application/dns-message")

		transport := &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: "cloudflare-dns.com",
			},
		}
		client := &http.Client{Transport: transport}

		resp, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("DoH request failed with status: %s", resp.Status)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, err
		}

		response := new(dns.Msg)
		if err := response.Unpack(body); err != nil {
			return nil, err
		}

		for _, ans := range response.Answer {
			switch a := ans.(type) {
			case *dns.A:
				ips = append(ips, a.A)
			case *dns.AAAA:
				ips = append(ips, a.AAAA)
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no IP addresses found for %s", host)
	}

	return ips, nil
}

package client

import (
	"context"
	"net"
	"net/http"
	"time"
)

func NewHTTPClient(ipv4 bool, ipv6 bool) *http.Client {
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
			return dialer.DialContext(ctx, network, addr)
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

package app

import (
	"context"
	"fmt"
	"io"
	"math"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"

	"github.com/idanyas/speedflare/internal/client"
	"github.com/idanyas/speedflare/internal/data"
	"github.com/idanyas/speedflare/internal/location"
	"github.com/idanyas/speedflare/internal/output"
)

func RunSpeedTest(client *http.Client, latencyAttempts int, workers int, singleConnection bool, jsonOutput bool, suppressIntro bool, hideIP bool) (*data.TestResult, error) {
	trace, err := location.GetServerTrace(client)
	if err != nil {
		return nil, fmt.Errorf("failed to get server info: %w", err)
	}

	locs, err := location.FetchLocations(client)
	if err != nil {
		return nil, fmt.Errorf("failed to get locations: %w", err)
	}

	server, err := location.FindServerInfo(trace["colo"], locs)
	if err != nil {
		return nil, err
	}

	if !suppressIntro {
		output.PrintConnectionInfo(trace, server, jsonOutput, hideIP)
	}

	latency, err := measureLatency(client, latencyAttempts)
	if err != nil {
		return nil, fmt.Errorf("latency test failed: %w", err)
	}
	output.PrintLatencyInfo(latency, jsonOutput)

	download := runTest("Download:", downloadWorker, client, !singleConnection, workers, jsonOutput)
	upload := runTest("Upload:", uploadWorker, client, !singleConnection, workers, jsonOutput)

	resultIP := trace["ip"]
	if hideIP {
		resultIP = "---"
	}

	return &data.TestResult{
		IP:     resultIP,
		Server: server,
		Latency: data.Stats{
			Value:  latency.Avg,
			Jitter: latency.Jitter,
			Min:    latency.Min,
			Max:    latency.Max,
		},
		Download: data.Speed{
			Mbps:   download.mbps,
			DataMB: download.dataMB,
		},
		Upload: data.Speed{
			Mbps:   upload.mbps,
			DataMB: upload.dataMB,
		},
	}, nil
}

func measureLatency(c *http.Client, latencyAttempts int) (*data.LatencyResult, error) {
	attempts := latencyAttempts
	var latencies []float64

	var transport *http.Transport
	if t, ok := c.Transport.(*http.Transport); ok {
		transport = t
	} else if t, ok := c.Transport.(*client.BrowserTransport); ok {
		transport = t.Transport
	} else {
		return nil, fmt.Errorf("invalid transport type, expected *http.Transport")
	}

	for i := 0; i < attempts; i++ {
		// Increased timeout significantly to 15s.
		// This handles slow DNS resolution and multiple IP failovers in the custom dialer.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		start := time.Now()
		conn, err := transport.DialContext(ctx, "tcp", "speed.cloudflare.com:443")
		if err != nil {
			cancel()
			return nil, fmt.Errorf("failed to dial server: %w", err)
		}
		conn.Close()
		cancel()
		latency := time.Since(start).Seconds() * 1000 // Convert to milliseconds
		latencies = append(latencies, latency)

		// Introduce random jitter between attempts (0-50ms)
		if i < attempts-1 {
			time.Sleep(time.Duration(rand.Intn(50)) * time.Millisecond)
		}
	}

	sum := 0.0
	min := math.MaxFloat64
	max := 0.0
	for _, l := range latencies {
		sum += l
		if l < min {
			min = l
		}
		if l > max {
			max = l
		}
	}
	avg := sum / float64(len(latencies))

	jitterSum := 0.0
	for _, l := range latencies {
		jitterSum += math.Abs(l - avg)
	}
	jitter := jitterSum / float64(len(latencies))

	return &data.LatencyResult{
		Avg:    avg,
		Jitter: jitter,
		Min:    min,
		Max:    max,
	}, nil
}

type testResult struct {
	mbps   float64
	dataMB float64
}

func runTest(name string, worker func(context.Context, *int64, *http.Client) testResult, client *http.Client, multiple bool, workers int, jsonOutput bool) testResult {
	var totalBytes int64
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	done := make(chan struct{})
	start := time.Now()

	var wg sync.WaitGroup
	numWorkers := 1
	if multiple {
		numWorkers = workers
	}

	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker(ctx, &totalBytes, client)
		}()
	}

	go func() {
		wg.Wait()
		close(done)
	}()

	go output.ProgressReporter(name, done, &totalBytes, start, jsonOutput)

	<-done
	duration := time.Since(start).Seconds()
	mbps := (float64(atomic.LoadInt64(&totalBytes)*8) / (duration * 1e6))
	dataMB := float64(atomic.LoadInt64(&totalBytes)) / 1e6

	if !jsonOutput {
		green := color.New(color.FgGreen).SprintFunc()
		fmt.Printf("\r%s %s %.2f Mbps (Used: %.2f MB)    \n",
			green("✓"),
			name,
			mbps,
			dataMB,
		)
	}

	return testResult{mbps, dataMB}
}

func downloadWorker(ctx context.Context, totalBytes *int64, client *http.Client) testResult {
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://speed.cloudflare.com/__down?bytes=2147483648", nil)
	resp, err := client.Do(req)
	if err != nil {
		return testResult{}
	}
	defer resp.Body.Close()

	buf := make([]byte, 32*1024)
	for {
		select {
		case <-ctx.Done():
			return testResult{}
		default:
			n, err := resp.Body.Read(buf)
			if err != nil {
				return testResult{}
			}
			atomic.AddInt64(totalBytes, int64(n))
		}
	}
}

func uploadWorker(ctx context.Context, totalBytes *int64, client *http.Client) testResult {
	pr, pw := io.Pipe()
	go func() {
		defer pw.Close()
		buf := make([]byte, 1<<20)
		rand.Read(buf)
		for {
			select {
			case <-ctx.Done():
				return
			default:
				n, _ := pw.Write(buf)
				atomic.AddInt64(totalBytes, int64(n))
			}
		}
	}()

	req, _ := http.NewRequest("POST", "https://speed.cloudflare.com/__up", pr)
	req = req.WithContext(ctx)
	_, err := client.Do(req)
	if err != nil {
		return testResult{}
	}
	return testResult{}
}

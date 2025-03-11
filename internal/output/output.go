package output

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/fatih/color"

	"github.com/idanyas/speedflare/internal/data"
	"github.com/idanyas/speedflare/internal/location"
)

func PrintHeader(jsonOutput bool) {
	if jsonOutput {
		return
	}
	cyan := color.New(color.FgCyan)
	cyan.Printf("\n    speedflare v0.1.0\n\n")
}

func ShowLocations(client *http.Client) {
	locs, err := location.FetchLocations(client)
	if err != nil {
		fmt.Printf("Error fetching locations: %v\n", err)
		return
	}

	fmt.Println("Cloudflare Server Locations:")
	fmt.Printf("%-5s %-15s %-8s %-15s\n", "IATA", "City", "Country", "Region")
	for _, loc := range locs {
		fmt.Printf("%-5s %-15s %-8s %-15s\n", loc.IATA, loc.City, loc.CCA2, loc.Region)
	}
}

func PrintConnectionInfo(trace map[string]string, server data.Server, jsonOutput bool) {
	if jsonOutput {
		return
	}
	cyan := color.New(color.FgCyan).SprintFunc()
	fmt.Printf("%s Your IP: %s [%s]\n", cyan("✓"), trace["ip"], trace["loc"])
	fmt.Printf("%s Server: %s, %s (%s) [%.4f, %.4f]\n\n",
		cyan("✓"),
		server.City,
		server.Country,
		server.IATA,
		server.Lat,
		server.Lon,
	)
}

func OutputJSON(results *data.TestResult) {
	jsonData, _ := json.MarshalIndent(results, "", "  ")
	fmt.Println(string(jsonData))
}

func PrintLatencyInfo(latency *data.LatencyResult, jsonOutput bool) {
	if jsonOutput {
		return
	}
	green := color.New(color.FgGreen).SprintFunc()
	fmt.Printf("%s Latency: %.2f ms (Jitter: %.2f ms, Min: %.2f ms, Max: %.2f ms)\n",
		green("✓"),
		latency.Avg,
		latency.Jitter,
		latency.Min,
		latency.Max,
	)
}

type latencyResult struct {
	avg    float64
	jitter float64
	min    float64
	max    float64
}

func ProgressReporter(name string, done <-chan struct{}, totalBytes *int64, start time.Time, jsonOutput bool) {
	if jsonOutput {
		return
	}
	cyan := color.New(color.FgCyan).SprintFunc()
	spinner := []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}
	i := 0

	for {
		select {
		case <-done:
			return
		default:
			time.Sleep(100 * time.Millisecond)
			bytes := atomic.LoadInt64(totalBytes)
			speed := (float64(bytes) * 8 / 1e6) / time.Since(start).Seconds()

			fmt.Printf("\r\033[K%s %s %6.2f Mbps",
				cyan(spinner[i]),
				name,
				speed,
			)
			i = (i + 1) % len(spinner)
		}
	}
}

package output

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync/atomic"
	"time"

	"github.com/fatih/color"

	"github.com/idanyas/speedflare/internal/data"
	"github.com/idanyas/speedflare/internal/location"
)

func PrintHeader(jsonOutput bool, version string) {
	if jsonOutput {
		return
	}
	cyan := color.New(color.FgCyan)
	cyan.Printf("\n    speedflare v%s\n\n", version)
}

func ShowLocations(client *http.Client) {
	locs, err := location.FetchLocations(client)
	if err != nil {
		fmt.Fprintf(os.Stdout, "Error fetching locations: %v\n", err)
		return
	}

	// Sort locations by CCA2 (2-letter country code)
	sort.Slice(locs, func(i, j int) bool {
		return locs[i].CCA2 < locs[j].CCA2
	})

	// Find maximum lengths from data
	maxIATA_from_data := 0
	maxCity_from_data := 0
	maxCountry_from_data := 0
	maxRegion_from_data := 0
	for _, loc := range locs {
		if len(loc.IATA) > maxIATA_from_data {
			maxIATA_from_data = len(loc.IATA)
		}
		if len(loc.City) > maxCity_from_data {
			maxCity_from_data = len(loc.City)
		}
		if len(loc.CCA2) > maxCountry_from_data {
			maxCountry_from_data = len(loc.CCA2)
		}
		if len(loc.Region) > maxRegion_from_data {
			maxRegion_from_data = len(loc.Region)
		}
	}

	// Set final maximum lengths considering headers
	maxIATA := func(a int) int {
		if len("IATA") > a {
			return len("IATA")
		}
		return a
	}(maxIATA_from_data)
	maxCity := func(a int) int {
		if len("City") > a {
			return len("City")
		}
		return a
	}(maxCity_from_data)
	maxCountry := func(a int) int {
		if len("Country") > a {
			return len("Country")
		}
		return a
	}(maxCountry_from_data)
	maxRegion := func(a int) int {
		if len("Region") > a {
			return len("Region")
		}
		return a
	}(maxRegion_from_data)

	// Print header
	fmt.Fprintf(os.Stdout, "%-*.*s ", maxIATA, maxIATA, "IATA")
	fmt.Fprintf(os.Stdout, "%-*.*s ", maxCity, maxCity, "City")
	fmt.Fprintf(os.Stdout, "%-*.*s ", maxCountry, maxCountry, "Country")
	fmt.Fprintf(os.Stdout, "%-*.*s\n", maxRegion, maxRegion, "Region")

	// Print each location
	for _, loc := range locs {
		fmt.Fprintf(os.Stdout, "%-*.*s ", maxIATA, maxIATA, loc.IATA)
		fmt.Fprintf(os.Stdout, "%-*.*s ", maxCity, maxCity, loc.City)
		fmt.Fprintf(os.Stdout, "%-*.*s ", maxCountry, maxCountry, loc.CCA2)
		fmt.Fprintf(os.Stdout, "%-*.*s\n", maxRegion, maxRegion, loc.Region)
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

			fmt.Printf("\r\033[K%s %s %.2f Mbps",
				cyan(spinner[i]),
				name,
				speed,
			)
			i = (i + 1) % len(spinner)
		}
	}
}

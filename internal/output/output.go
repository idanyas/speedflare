package output

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"strings"
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

// ShowLocations now accepts jsonOutput flag
func ShowLocations(client *http.Client, jsonOutput bool) {
	locs, err := location.FetchLocations(client)
	if err != nil {
		// Output error to stderr
		fmt.Fprintf(os.Stderr, "Error fetching locations: %v\n", err)
		// Exit or return? Let's return for now, main handles exit.
		return
	}

	// Sort locations by CCA2 (2-letter country code) then City for consistent output
	sort.Slice(locs, func(i, j int) bool {
		// Primary sort by Country (CCA2), secondary by City
		if locs[i].CCA2 != locs[j].CCA2 {
			return locs[i].CCA2 < locs[j].CCA2
		}
		return locs[i].City < locs[j].City
	})

	// If JSON output is requested, marshal and print
	if jsonOutput {
		jsonData, err := json.MarshalIndent(locs, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling locations to JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonData))
		return // Don't print the table
	}

	// --- Table Output Logic (only if not jsonOutput) ---

	// Find maximum lengths from data
	maxIATA := len("IATA")
	maxCity := len("City")
	maxCountry := len("Country")
	maxRegion := len("Region")
	for _, loc := range locs {
		if len(loc.IATA) > maxIATA {
			maxIATA = len(loc.IATA)
		}
		if len(loc.City) > maxCity {
			maxCity = len(loc.City)
		}
		// Use CCA2 for Country column width calculation
		if len(loc.CCA2) > maxCountry {
			maxCountry = len(loc.CCA2)
		}
		if len(loc.Region) > maxRegion {
			maxRegion = len(loc.Region)
		}
	}

	// Create format strings dynamically
	headerFmt := fmt.Sprintf("%%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds\n",
		maxIATA, maxIATA, maxCity, maxCity, maxCountry, maxCountry, maxRegion, maxRegion)
	lineFmt := fmt.Sprintf("%%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds\n",
		maxIATA, maxIATA, maxCity, maxCity, maxCountry, maxCountry, maxRegion, maxRegion)

	// Print header
	fmt.Fprintf(os.Stdout, headerFmt, "IATA", "City", "Country", "Region")

	// Print separator line
	fmt.Fprintf(os.Stdout, "%s %s %s %s\n",
		strings.Repeat("-", maxIATA),
		strings.Repeat("-", maxCity),
		strings.Repeat("-", maxCountry),
		strings.Repeat("-", maxRegion),
	)

	// Print each location
	for _, loc := range locs {
		fmt.Fprintf(os.Stdout, lineFmt, loc.IATA, loc.City, loc.CCA2, loc.Region)
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
	// MarshalIndent handles potential errors internally by returning null/empty objects.
	// For critical failure, it might return an error, but usually, it produces valid JSON.
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

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			// The final result print will overwrite this line.
			return
		case <-ticker.C:
			bytes := atomic.LoadInt64(totalBytes)
			elapsed := time.Since(start).Seconds()
			var speed float64
			// Avoid division by zero or negative elapsed time if clock jumps
			if elapsed > 0 {
				speed = (float64(bytes) * 8 / 1e6) / elapsed
			} else {
				speed = 0.0
			}

			// \r moves cursor to beginning, \033[K clears line from cursor to end
			fmt.Printf("\r\033[K%s %s %.2f Mbps",
				cyan(spinner[i%len(spinner)]), // Use modulo for safety
				name,
				speed,
			)
			i++
		}
	}
}

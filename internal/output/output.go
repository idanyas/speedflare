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
	"github.com/manifoldco/promptui"

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

func ShowLocations(client *http.Client, jsonOutput bool) {
	locs, err := location.FetchLocations(client)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error fetching locations: %v\n", err)
		return
	}

	sort.Slice(locs, func(i, j int) bool {
		if locs[i].CCA2 != locs[j].CCA2 {
			return locs[i].CCA2 < locs[j].CCA2
		}
		return locs[i].City < locs[j].City
	})

	if jsonOutput {
		jsonData, err := json.MarshalIndent(locs, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error marshaling locations to JSON: %v\n", err)
			return
		}
		fmt.Println(string(jsonData))
		return
	}

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
		if len(loc.CCA2) > maxCountry {
			maxCountry = len(loc.CCA2)
		}
		if len(loc.Region) > maxRegion {
			maxRegion = len(loc.Region)
		}
	}

	headerFmt := fmt.Sprintf("%%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds\n",
		maxIATA, maxIATA, maxCity, maxCity, maxCountry, maxCountry, maxRegion, maxRegion)
	lineFmt := fmt.Sprintf("%%-%d.%ds %%-%d.%ds %%-%d.%ds %%-%d.%ds\n",
		maxIATA, maxIATA, maxCity, maxCity, maxCountry, maxCountry, maxRegion, maxRegion)

	fmt.Fprintf(os.Stdout, headerFmt, "IATA", "City", "Country", "Region")
	fmt.Fprintf(os.Stdout, "%s %s %s %s\n",
		strings.Repeat("-", maxIATA),
		strings.Repeat("-", maxCity),
		strings.Repeat("-", maxCountry),
		strings.Repeat("-", maxRegion),
	)
	for _, loc := range locs {
		fmt.Fprintf(os.Stdout, lineFmt, loc.IATA, loc.City, loc.CCA2, loc.Region)
	}
}

func PrintClientInfo(trace map[string]string, jsonOutput bool, hideIP bool) {
	if jsonOutput {
		return
	}

	ipStr := trace["ip"]
	if hideIP {
		ipStr = "---"
	}

	warpStatus := ""
	if trace["warp"] == "on" {
		if trace["gateway"] == "on" {
			warpStatus = ", Zero Trust WARP"
		} else {
			warpStatus = ", WARP"
		}
	}

	cyan := color.New(color.FgCyan).SprintFunc()
	fmt.Printf("%s Your IP: %s [%s]%s\n", cyan("✓"), ipStr, trace["loc"], warpStatus)
}

func PrintConnectionInfo(trace map[string]string, server data.Server, jsonOutput bool, hideIP bool) {
	if jsonOutput {
		return
	}
	PrintClientInfo(trace, jsonOutput, hideIP)
	
	if server.IATA != "" {
		cyan := color.New(color.FgCyan).SprintFunc()
		fmt.Printf("%s Server: %s, %s (%s) [%.4f, %.4f]\n\n",
			cyan("✓"),
			server.City,
			server.Country,
			server.IATA,
			server.Lat,
			server.Lon,
		)
	} else {
		fmt.Println()
	}
}

func SelectServer(servers []data.Server) int {
	cyan := color.New(color.FgCyan).SprintFunc()
	fmt.Printf("%s This network seems to be fragmented, please choose a datacenter:\n", cyan("✓"))

	// 1. Calculate the maximum length of the City name for alignment
	maxCityLen := 0
	for _, s := range servers {
		if len(s.City) > maxCityLen {
			maxCityLen = len(s.City)
		}
	}
	// We want "City," so we add 1 for the comma
	padWidth := maxCityLen + 1

	// 2. Generate dynamic templates with fixed width padding
	// Logic: {{ printf "%s," .City | printf "%-Ns" }} adds the comma, then pads to N width
	activeTpl := fmt.Sprintf(`{{ "▸" | cyan }} {{ printf "%%s," .City | printf "%%-%ds" | cyan }} {{ .Country | cyan }} ({{ .IATA | cyan }}) [{{ .Distance | printf "%%.0f" }} km]`, padWidth)
	inactiveTpl := fmt.Sprintf(`  {{ printf "%%s," .City | printf "%%-%ds" }} {{ .Country }} ({{ .IATA }}) [{{ .Distance | printf "%%.0f" }} km]`, padWidth)

	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}",
		Active:   activeTpl,
		Inactive: inactiveTpl,
	}

	prompt := promptui.Select{
		Label:        "",
		Items:        servers,
		Templates:    templates,
		Size:         10,
		HideHelp:     true,
		Stdout:       os.Stdout,
		HideSelected: true, 
	}

	i, _, err := prompt.Run()
	if err != nil {
		if err == promptui.ErrInterrupt {
			os.Exit(0)
		}
		return 0
	}

	// Move cursor up one line and clear
	fmt.Print("\033[1A\033[2K\r")

	green := color.New(color.FgGreen).SprintFunc()
	s := servers[i]
	fmt.Printf("%s Server: %s, %s (%s) [%.4f, %.4f]\n",
		green("✓"),
		s.City,
		s.Country,
		s.IATA,
		s.Lat,
		s.Lon,
	)

	return i
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

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			bytes := atomic.LoadInt64(totalBytes)
			elapsed := time.Since(start).Seconds()
			var speed float64
			if elapsed > 0 {
				speed = (float64(bytes) * 8 / 1e6) / elapsed
			} else {
				speed = 0.0
			}

			fmt.Printf("\r\033[K%s %s %.2f Mbps",
				cyan(spinner[i%len(spinner)]),
				name,
				speed,
			)
			i++
		}
	}
}

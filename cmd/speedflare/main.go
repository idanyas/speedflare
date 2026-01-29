package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/pflag"

	"github.com/idanyas/speedflare/internal/app"
	"github.com/idanyas/speedflare/internal/client"
	"github.com/idanyas/speedflare/internal/location"
	"github.com/idanyas/speedflare/internal/output"
)

var (
	version          = "DEV"
	jsonOutput       = pflag.BoolP("json", "j", false, "Output results in JSON format.")
	list             = pflag.Bool("list", false, "List all Cloudflare server locations.")
	ipv4             = pflag.BoolP("ipv4", "4", false, "Use IPv4 only connection.")
	ipv6             = pflag.BoolP("ipv6", "6", false, "Use IPv6 only connection.")
	interfaceName    = pflag.StringP("interface", "I", "", "Network interface or source IP address to use.")
	latencyAttempts  = pflag.IntP("latency-attempts", "l", 10, "Number of latency attempts.")
	singleConnection = pflag.BoolP("single", "s", false, "Use a single connection instead of multiple.")
	workers          = pflag.IntP("workers", "w", 6, "Number of workers for multithreaded speedtests.")
	insecure         = pflag.Bool("insecure", false, "Skip TLS certificate verification (UNSAFE).")
	hideIP           = pflag.Bool("hide-ip", false, "Hide the IP address in output.")
)

func main() {
	pflag.Usage = func() {
		out := os.Stderr
		fmt.Fprintf(out, "Usage: %s [options...]\n\n", os.Args[0])
		fmt.Fprintln(out, "Measure network speed using Cloudflare's network.")
		fmt.Fprintln(out, "\nOptions:")
		pflag.PrintDefaults()
		fmt.Fprintf(out, "\nVersion: %s\n", version)
		fmt.Fprintln(out, "Homepage: https://github.com/idanyas/speedflare")
	}
	pflag.CommandLine.Init(os.Args[0], pflag.ContinueOnError)
	err := pflag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		if err == pflag.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "\nError parsing flags: %v\n", err)
		os.Exit(2)
	}

	if *ipv4 && *ipv6 {
		fmt.Fprintln(os.Stderr, "Error: --ipv4 (-4) and --ipv6 (-6) flags cannot be used together.")
		os.Exit(2)
	}

	effectiveInterfaceName := *interfaceName
	if ip := net.ParseIP(*interfaceName); ip != nil {
		effectiveInterfaceName = *interfaceName
	}

	if *singleConnection {
		if pflag.CommandLine.Changed("workers") {
			if !*jsonOutput {
				yellow := color.New(color.FgYellow).FprintfFunc()
				yellow(os.Stderr, "Warning: --workers (-w) flag is ignored when --single (-s) is used.\n")
			}
		}
		*workers = 1
	}

	if *workers <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --workers (-w) must be a positive number.")
		os.Exit(2)
	}
	if *latencyAttempts <= 0 {
		fmt.Fprintln(os.Stderr, "Error: --latency-attempts (-l) must be a positive number.")
		os.Exit(2)
	}

	output.PrintHeader(*jsonOutput, version)

	if *insecure && !*jsonOutput {
		yellow := color.New(color.FgYellow).FprintfFunc()
		yellow(os.Stderr, "Warning: Skipping TLS certificate verification (--insecure). This is potentially unsafe!\n")
	}

	// Initial Client Creation (for trace and location fetching)
	httpClient, err := client.NewHTTPClient(*ipv4, *ipv6, effectiveInterfaceName, *insecure, "")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating HTTP client: %v\n", err)
		handleClientError(err, effectiveInterfaceName)
		os.Exit(1)
	}

	if *list {
		output.ShowLocations(httpClient, *jsonOutput)
		os.Exit(0)
	}

	// 1. Get basic info
	trace, err := location.GetServerTrace(httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting trace: %v\n", err)
		os.Exit(1)
	}

	locs, err := location.FetchLocations(httpClient)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting locations: %v\n", err)
		os.Exit(1)
	}

	// 2. Resolve User Location
	// Using a dedicated/clean client logic inside GetUserCoordinates now.
	userLat, userLon, geoErr := location.GetUserCoordinates()
	if geoErr != nil && !*jsonOutput {
		// Log warning but continue to fallback logic
		yellow := color.New(color.FgYellow).FprintfFunc()
		yellow(os.Stderr, "Warning: GeoIP lookup failed (%v). Falling back to Cloudflare estimated location.\n", geoErr)
	}

	// 3. Probe for Fragmentation
	forcedIP := ""
	suppressIntro := false

	if !*ipv6 {
		// Pass Coordinates + Trace Colo + Trace Country + Locations Lib
		servers, err := location.ProbeColos(userLat, userLon, trace["colo"], trace["loc"], locs)
		if err == nil && len(servers) > 1 {
			// Ask user to choose
			if !*jsonOutput {
				output.PrintClientInfo(trace, *jsonOutput, *hideIP)

				idx := output.SelectServer(servers)
				selected := servers[idx]
				forcedIP = selected.IP

				// Re-create client with forced IP
				httpClient, err = client.NewHTTPClient(*ipv4, *ipv6, effectiveInterfaceName, *insecure, forcedIP)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error creating client for selected colo: %v\n", err)
					os.Exit(1)
				}

				suppressIntro = true
				fmt.Println()
			}
		}
	}

	// Run the speed test
	results, err := app.RunSpeedTest(httpClient, *latencyAttempts, *workers, *singleConnection, *jsonOutput, suppressIntro, *hideIP)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error during speed test: %v\n", err)
		handleClientError(err, effectiveInterfaceName)
		if !*insecure && (strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "tls")) {
			fmt.Fprintln(os.Stderr, "Hint: If you trust the network, try the --insecure flag (use with caution).")
		} else if strings.Contains(err.Error(), "certificate signed by unknown authority") {
			fmt.Fprintln(os.Stderr, "Hint: System's root CA certificates might be missing or outdated.")
			fmt.Fprintln(os.Stderr, "Hint: If you trust the network, try the --insecure flag (use with caution).")
		}
		os.Exit(1)
	}

	if *jsonOutput {
		output.OutputJSON(results)
	}
}

func handleClientError(err error, iface string) {
	if strings.Contains(err.Error(), "failed to find interface") {
		fmt.Fprintln(os.Stderr, "Hint: Ensure the specified interface name exists and is correct.")
	} else if strings.Contains(err.Error(), "no suitable IP address found") {
		fmt.Fprintf(os.Stderr, "Hint: Check if interface %q has an IP address matching the requested family (IPv4/IPv6).\n", iface)
	} else if _, ok := err.(*net.DNSError); ok || strings.Contains(err.Error(), "DNS resolution failed") {
		fmt.Fprintln(os.Stderr, "Hint: Check network connectivity and DNS settings. Try forcing IPv4 (-4) or IPv6 (-6).")
	} else if strings.Contains(err.Error(), "connection failed") || strings.Contains(err.Error(), "dial tcp") {
		fmt.Fprintln(os.Stderr, "Hint: Check network connectivity, firewall rules, or try specifying a source IP/interface with -I.")
	}
}

package main

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/spf13/pflag"

	"github.com/idanyas/speedflare/internal/app"
	"github.com/idanyas/speedflare/internal/client"
	"github.com/idanyas/speedflare/internal/output"
)

var (
	version          = "DEV"
	jsonOutput       = pflag.BoolP("json", "j", false, "Output results in JSON format.")
	list             = pflag.Bool("list", false, "List all Cloudflare server locations.")
	ipv4             = pflag.BoolP("ipv4", "4", false, "Use IPv4 only connection.")
	ipv6             = pflag.BoolP("ipv6", "6", false, "Use IPv6 only connection.")
	interfaceName    = pflag.StringP("interface", "I", "", "Network interface to use for the test.") // New flag
	latencyAttempts  = pflag.IntP("latency-attempts", "l", 10, "Number of latency attempts.")
	singleConnection = pflag.BoolP("single", "s", false, "Use a single connection instead of multiple.")
	workers          = pflag.IntP("workers", "w", 6, "Number of workers for multithreaded speedtests.")
)

func main() {
	pflag.Usage = func() {
		// Keep consistent formatting for help output
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
			os.Exit(0) // Exit cleanly on help request
		}
		// Don't print usage here, pflag does it on ContinueOnError
		fmt.Fprintf(os.Stderr, "Error parsing flags: %v\n", err)
		os.Exit(2) // Use standard exit code for CLI errors
	}

	if *ipv4 && *ipv6 {
		fmt.Fprintln(os.Stderr, "Error: --ipv4 (-4) and --ipv6 (-6) flags cannot be used together.")
		os.Exit(2)
	}

	if *singleConnection && *workers != 6 { // Default value check might be fragile, better check if flag was explicitly set
		if pflag.CommandLine.Changed("workers") {
			fmt.Fprintln(os.Stderr, "Warning: --workers (-w) flag is ignored when --single (-s) is used.")
		}
		*workers = 1 // Force workers to 1 if single connection is requested
	} else if *singleConnection {
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

	// Pass interface name to client creation
	httpClient, err := client.NewHTTPClient(*ipv4, *ipv6, *interfaceName)
	if err != nil {
		// Print errors to stderr
		fmt.Fprintf(os.Stderr, "Error creating HTTP client: %v\n", err)
		os.Exit(1)
	}

	if *list {
		// Pass jsonOutput flag to ShowLocations
		// ShowLocations handles printing errors to stderr if needed
		output.ShowLocations(httpClient, *jsonOutput)
		return // Exit after listing locations
	}

	// Run the speed test
	results, err := app.RunSpeedTest(httpClient, *latencyAttempts, *workers, *singleConnection, *jsonOutput)
	if err != nil {
		// Use Fprintf for stderr for application errors too
		// Ensure the error message clearly indicates the stage (e.g., trace, latency, download)
		fmt.Fprintf(os.Stderr, "Error during speed test: %v\n", err)
		// Check specifically for DNS resolution errors within the client connection phase if possible,
		// although the detailed error should bubble up from client.go via app.RunSpeedTest
		if _, ok := err.(*net.DNSError); ok || strings.Contains(err.Error(), "DNS resolution failed") {
			fmt.Fprintln(os.Stderr, "Hint: Check network connectivity and DNS settings.")
		} else if strings.Contains(err.Error(), "connection failed") || strings.Contains(err.Error(), "dial tcp") {
			fmt.Fprintln(os.Stderr, "Hint: Check network connectivity, firewall rules, or try specifying an interface with -I.")
		}

		os.Exit(1)
	}

	// Output results if not already handled (e.g., non-JSON output prints as it goes)
	if *jsonOutput {
		output.OutputJSON(results)
	}
}

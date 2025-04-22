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
	"github.com/idanyas/speedflare/internal/output"
)

var (
	version          = "DEV"
	jsonOutput       = pflag.BoolP("json", "j", false, "Output results in JSON format.")
	list             = pflag.Bool("list", false, "List all Cloudflare server locations.")
	ipv4             = pflag.BoolP("ipv4", "4", false, "Use IPv4 only connection.")
	ipv6             = pflag.BoolP("ipv6", "6", false, "Use IPv6 only connection.")
	interfaceName    = pflag.StringP("interface", "I", "", "Network interface or source IP address to use.") // Updated description
	latencyAttempts  = pflag.IntP("latency-attempts", "l", 10, "Number of latency attempts.")
	singleConnection = pflag.BoolP("single", "s", false, "Use a single connection instead of multiple.")
	workers          = pflag.IntP("workers", "w", 6, "Number of workers for multithreaded speedtests.")
	insecure         = pflag.Bool("insecure", false, "Skip TLS certificate verification (UNSAFE).") // New flag
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
		// pflag prints usage on error with ContinueOnError
		fmt.Fprintf(os.Stderr, "\nError parsing flags: %v\n", err)
		os.Exit(2) // Use standard exit code for CLI errors
	}

	if *ipv4 && *ipv6 {
		fmt.Fprintln(os.Stderr, "Error: --ipv4 (-4) and --ipv6 (-6) flags cannot be used together.")
		os.Exit(2)
	}

	// If interface flag looks like an IP address, treat it as such for client binding.
	// Otherwise, treat it as an interface name. client.getLocalAddr handles names.
	effectiveInterfaceName := *interfaceName
	if ip := net.ParseIP(*interfaceName); ip != nil {
		// It's a valid IP address, let the dialer use it directly.
		// client.NewHTTPClient's dialer setup will create a net.TCPAddr from it.
		// For simplicity, we pass the IP string; getLocalAddr will return nil,
		// but the dialer's LocalAddr will be set correctly later if it's an IP.
		// We could parse it here and create the TCPAddr, but let's keep it simple.
		effectiveInterfaceName = *interfaceName // Pass the IP string
	}

	// If single connection is set, warn if workers is also set, and force workers to 1.
	if *singleConnection {
		if pflag.CommandLine.Changed("workers") {
			// Only warn if user explicitly set --workers with --single
			if !*jsonOutput { // Don't print warnings in JSON mode
				yellow := color.New(color.FgYellow).FprintfFunc()
				yellow(os.Stderr, "Warning: --workers (-w) flag is ignored when --single (-s) is used.\n")
			}
		}
		*workers = 1 // Force workers to 1 if single connection is requested
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

	// Warn if insecure flag is used
	if *insecure && !*jsonOutput {
		yellow := color.New(color.FgYellow).FprintfFunc()
		yellow(os.Stderr, "Warning: Skipping TLS certificate verification (--insecure). This is potentially unsafe!\n")
	}

	// Pass interface name/IP and insecure flag to client creation
	httpClient, err := client.NewHTTPClient(*ipv4, *ipv6, effectiveInterfaceName, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating HTTP client: %v\n", err)
		// Provide hints based on common errors
		if strings.Contains(err.Error(), "failed to find interface") {
			fmt.Fprintln(os.Stderr, "Hint: Ensure the specified interface name exists and is correct.")
		} else if strings.Contains(err.Error(), "no suitable IP address found") {
			fmt.Fprintf(os.Stderr, "Hint: Check if interface %q has an IP address matching the requested family (IPv4/IPv6).\n", effectiveInterfaceName)
		}
		os.Exit(1)
	}

	if *list {
		// Pass jsonOutput flag to ShowLocations
		// ShowLocations handles printing errors to stderr if needed
		output.ShowLocations(httpClient, *jsonOutput)
		os.Exit(0) // Exit cleanly after listing locations
	}

	// Run the speed test
	results, err := app.RunSpeedTest(httpClient, *latencyAttempts, *workers, *singleConnection, *jsonOutput)
	if err != nil {
		// Use Fprintf for stderr for application errors too
		fmt.Fprintf(os.Stderr, "Error during speed test: %v\n", err)

		// Provide hints based on common errors
		if _, ok := err.(*net.DNSError); ok || strings.Contains(err.Error(), "DNS resolution failed") {
			fmt.Fprintln(os.Stderr, "Hint: Check network connectivity and DNS settings. Try forcing IPv4 (-4) or IPv6 (-6).")
		} else if strings.Contains(err.Error(), "connection failed") || strings.Contains(err.Error(), "dial tcp") {
			fmt.Fprintln(os.Stderr, "Hint: Check network connectivity, firewall rules, or try specifying a source IP/interface with -I.")
			if !*insecure && (strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "tls")) {
				fmt.Fprintln(os.Stderr, "Hint: If you trust the network, try the --insecure flag (use with caution).")
			}
		} else if strings.Contains(err.Error(), "certificate signed by unknown authority") {
			fmt.Fprintln(os.Stderr, "Hint: System's root CA certificates might be missing or outdated.")
			fmt.Fprintln(os.Stderr, "Hint: If you trust the network, try the --insecure flag (use with caution).")
		}

		os.Exit(1)
	}

	// Output final JSON results if requested
	if *jsonOutput {
		output.OutputJSON(results)
	}
}

package main

import (
	"fmt"
	"os"

	"github.com/spf13/pflag"

	"github.com/idanyas/speedflare/internal/app"
	"github.com/idanyas/speedflare/internal/client"
	"github.com/idanyas/speedflare/internal/output"
)

var (
	jsonOutput      = pflag.BoolP("json", "j", false, "Output results in JSON format.")
	list            = pflag.Bool("list", false, "List all Cloudflare server locations.")
	ipv4            = pflag.BoolP("ipv4", "4", false, "Use IPv4 only connection.")
	ipv6            = pflag.BoolP("ipv6", "6", false, "Use IPv6 only connection.")
	latencyAttempts = pflag.IntP("latency-attempts", "l", 10, "Number of latency attempts.")
	singleConnection = pflag.BoolP("single", "s", false, "Use a single connection instead of multiple.")
	workers         = pflag.IntP("workers", "w", 4, "Number of workers for multithreaded speedtests.")
)

func main() {
	pflag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options...]\n\n", os.Args[0])
		fmt.Fprintln(os.Stderr, "Options:")
		pflag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nCreated by idanya, https://idanya.ru (v0.1.0)")
	}
	pflag.CommandLine.Init(os.Args[0], pflag.ContinueOnError)
	err := pflag.CommandLine.Parse(os.Args[1:])
	if err != nil {
		if err == pflag.ErrHelp {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(2)
	}

	output.PrintHeader(*jsonOutput)

	if *list {
		httpClient := client.NewHTTPClient(*ipv4, *ipv6)
		output.ShowLocations(httpClient)
		return
	}

	httpClient := client.NewHTTPClient(*ipv4, *ipv6)

	results, err := app.RunSpeedTest(httpClient, *latencyAttempts, *workers, *singleConnection, *jsonOutput)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		output.OutputJSON(results)
	}
}

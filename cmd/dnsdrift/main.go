package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/prdp1137/dnsdrift/internal/output"
	"github.com/prdp1137/dnsdrift/internal/resolver"
	"github.com/prdp1137/dnsdrift/internal/scanner"
	"github.com/prdp1137/dnsdrift/internal/signature"
)

var version = "dev"

func main() {
	domainList := flag.String("l", "", "File containing list of subdomains (one per line)")
	domain := flag.String("d", "", "Single domain to scan")
	resolverFile := flag.String("r", "", "File containing resolver IPs (Trickest format, one per line)")
	workers := flag.Int("w", 100, "Number of concurrent workers")
	timeoutSec := flag.Int("timeout", 10, "Timeout per request in seconds")
	rateLimit := flag.Int("rate-limit", 0, "Max domains per second (0 = unlimited)")
	signatures := flag.String("signatures", "", "Custom signatures YAML file (overrides built-in)")
	outputFormat := flag.String("o", "table", "Output format: table, json")
	progress := flag.Bool("progress", true, "Show progress on stderr")
	showVersion := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, `dnsdrift v%s — subdomain takeover scanner

Usage:
  dnsdrift -l subdomains.txt [-r resolvers.txt] [-w 500]
  dnsdrift -d example.com
  subfinder -d example.com | dnsdrift [-r resolvers.txt]

Flags:
`, version)
		flag.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nExamples:")
		fmt.Fprintln(os.Stderr, "  dnsdrift -l subs.txt -r resolvers.txt -w 500 -o json")
		fmt.Fprintln(os.Stderr, "  subfinder -d target.com | dnsdrift -r resolvers.txt --progress")
		fmt.Fprintln(os.Stderr, "  dnsdrift -d vulnerable.example.com")
	}

	flag.Parse()

	if *showVersion {
		fmt.Printf("dnsdrift %s\n", version)
		os.Exit(0)
	}

	hasStdin := !isTerminal(os.Stdin)
	if *domainList == "" && *domain == "" && !hasStdin {
		fmt.Fprintln(os.Stderr, "Error: provide domains via -l <file>, -d <domain>, or stdin pipe")
		flag.Usage()
		os.Exit(1)
	}

	sigs, err := signature.LoadSignatures(*signatures)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signatures: %v\n", err)
		os.Exit(1)
	}

	timeout := time.Duration(*timeoutSec) * time.Second
	res, err := resolver.New(*resolverFile, timeout, 2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating resolver: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "dnsdrift v%s | %d signatures | %d resolvers | %d workers\n",
		version, len(sigs), res.ResolverCount(), *workers)

	cfg := scanner.Config{
		Workers:   *workers,
		Timeout:   timeout,
		RateLimit: *rateLimit,
		Progress:  *progress,
	}
	s := scanner.New(cfg, res, sigs)

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()

	format := output.FormatTable
	if strings.ToLower(*outputFormat) == "json" {
		format = output.FormatJSON
	}

	w := output.NewWriter(format, os.Stdout)
	w.WriteHeader()

	var results <-chan scanner.Result
	if *domainList != "" {
		results, err = s.ScanFile(ctx, *domainList)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	} else if *domain != "" {
		results = s.Scan(ctx, strings.NewReader(*domain))
	} else {
		results = s.Scan(ctx, os.Stdin)
	}

	for result := range results {
		if result.Finding != nil {
			w.WriteFinding(result.Finding)
		}
	}

	w.WriteFooter()

	scanned, findings := s.Stats()
	fmt.Fprintf(os.Stderr, "\nScan complete: %d domains scanned, %d findings\n", scanned, findings)

	if findings > 0 {
		os.Exit(2)
	}
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return true
	}
	return info.Mode()&os.ModeCharDevice != 0
}

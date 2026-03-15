package scanner

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prdp1137/dnsdrift/internal/domain"
	"github.com/prdp1137/dnsdrift/internal/finding"
	"github.com/prdp1137/dnsdrift/internal/httpclient"
	"github.com/prdp1137/dnsdrift/internal/resolver"
	"github.com/prdp1137/dnsdrift/internal/signature"
)

var confidenceRank = map[signature.Confidence]int{
	signature.Confirmed:  3,
	signature.Potential:  2,
	signature.Unlikely:   1,
	signature.Unverified: 0,
}

type Config struct {
	Workers   int
	Timeout   time.Duration
	RateLimit int
	Progress  bool
}

type Scanner struct {
	config     Config
	resolver   *resolver.Resolver
	httpClient *httpclient.Client
	signatures []signature.SignatureDef

	scanned   atomic.Int64
	findings  atomic.Int64
	startTime time.Time
}

func New(cfg Config, res *resolver.Resolver, sigs []signature.SignatureDef) *Scanner {
	return &Scanner{
		config:     cfg,
		resolver:   res,
		httpClient: httpclient.New(cfg.Timeout),
		signatures: sigs,
	}
}

type Result struct {
	Finding *finding.Finding
	Err     error
}

func (s *Scanner) Scan(ctx context.Context, reader io.Reader) <-chan Result {
	results := make(chan Result, s.config.Workers*2)

	go func() {
		defer close(results)
		s.startTime = time.Now()

		domains := make(chan string, s.config.Workers*4)
		go func() {
			defer close(domains)
			seen := make(map[string]struct{})
			scanner := bufio.NewScanner(reader)
			for scanner.Scan() {
				line := strings.TrimSpace(strings.ToLower(scanner.Text()))
				if line == "" || strings.HasPrefix(line, "#") {
					continue
				}
				if _, dup := seen[line]; dup {
					continue
				}
				seen[line] = struct{}{}
				select {
				case domains <- line:
				case <-ctx.Done():
					return
				}
			}
		}()

		var limiter <-chan time.Time
		if s.config.RateLimit > 0 {
			ticker := time.NewTicker(time.Second / time.Duration(s.config.RateLimit))
			defer ticker.Stop()
			limiter = ticker.C
		}

		var wg sync.WaitGroup
		sem := make(chan struct{}, s.config.Workers)

		for name := range domains {
			if ctx.Err() != nil {
				break
			}

			if limiter != nil {
				select {
				case <-limiter:
				case <-ctx.Done():
					break
				}
			}

			sem <- struct{}{}
			wg.Add(1)

			go func(domainName string) {
				defer wg.Done()
				defer func() { <-sem }()

				s.scanDomain(ctx, domainName, results)
				count := s.scanned.Add(1)

				if s.config.Progress && count%1000 == 0 {
					elapsed := time.Since(s.startTime).Seconds()
					rate := float64(count) / elapsed
					fmt.Fprintf(os.Stderr, "\r[dnsdrift] %d scanned | %d findings | %.0f domains/sec",
						count, s.findings.Load(), rate)
				}
			}(name)
		}

		wg.Wait()

		if s.config.Progress {
			elapsed := time.Since(s.startTime).Seconds()
			rate := float64(s.scanned.Load()) / elapsed
			fmt.Fprintf(os.Stderr, "\r[dnsdrift] %d scanned | %d findings | %.0f domains/sec | done\n",
				s.scanned.Load(), s.findings.Load(), rate)
		}
	}()

	return results
}

func (s *Scanner) ScanFile(ctx context.Context, path string) (<-chan Result, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening domain list: %w", err)
	}
	results := s.Scan(ctx, f)
	wrappedResults := make(chan Result, cap(results))
	go func() {
		defer f.Close()
		defer close(wrappedResults)
		for r := range results {
			wrappedResults <- r
		}
	}()
	return wrappedResults, nil
}

func (s *Scanner) Stats() (scanned int64, findings int64) {
	return s.scanned.Load(), s.findings.Load()
}

func (s *Scanner) scanDomain(ctx context.Context, name string, results chan<- Result) {
	d := &domain.Domain{Name: name}

	if err := s.resolver.Resolve(ctx, d); err != nil {
		return
	}

	bestPerType := make(map[string]*finding.Finding)

	for i := range s.signatures {
		sig := &s.signatures[i]

		if !sig.Potential(d) {
			continue
		}

		matched, err := sig.Check(ctx, d, s.resolver, s.httpClient)
		if err != nil || !matched {
			continue
		}

		f := &finding.Finding{
			Domain:     name,
			Service:    sig.Service,
			Signature:  sig.Name,
			Confidence: sig.Confidence,
			Info:       sig.GenerateInfo(),
			CNAMES:     d.CNAMES,
			A:          d.A,
			AAAA:       d.AAAA,
			NS:         d.NS,
		}

		existing, exists := bestPerType[sig.Type]
		if !exists || confidenceRank[f.Confidence] > confidenceRank[existing.Confidence] {
			bestPerType[sig.Type] = f
		}
	}

	for _, f := range bestPerType {
		s.findings.Add(1)
		results <- Result{Finding: f}
	}
}

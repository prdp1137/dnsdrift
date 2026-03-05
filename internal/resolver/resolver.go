package resolver

import (
	"bufio"
	"context"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
	"github.com/prdp1137/dnsdrift/internal/domain"
)

type Resolver struct {
	resolvers []string
	counter   atomic.Uint64
	timeout   time.Duration
	retries   int
}

func New(resolverFile string, timeout time.Duration, retries int) (*Resolver, error) {
	r := &Resolver{
		timeout: timeout,
		retries: retries,
	}

	if resolverFile != "" {
		resolvers, err := loadResolvers(resolverFile)
		if err != nil {
			return nil, err
		}
		r.resolvers = resolvers
	} else {
		r.resolvers = []string{"8.8.8.8:53", "1.1.1.1:53", "8.8.4.4:53", "1.0.0.1:53"}
	}

	if len(r.resolvers) == 0 {
		return nil, fmt.Errorf("no resolvers loaded")
	}

	return r, nil
}

func (r *Resolver) ResolverCount() int {
	return len(r.resolvers)
}

func (r *Resolver) nextResolver() string {
	idx := r.counter.Add(1)
	return r.resolvers[idx%uint64(len(r.resolvers))]
}

func (r *Resolver) Resolve(ctx context.Context, d *domain.Domain) error {
	name := dns.Fqdn(d.Name)

	var wg sync.WaitGroup
	wg.Add(4)

	go func() {
		defer wg.Done()
		if cnames, err := r.queryCNAME(ctx, name); err == nil {
			d.CNAMES = cnames
		}
	}()

	go func() {
		defer wg.Done()
		if aRecords, err := r.queryA(ctx, name); err == nil {
			d.A = aRecords
		}
	}()

	go func() {
		defer wg.Done()
		if aaaaRecords, err := r.queryAAAA(ctx, name); err == nil {
			d.AAAA = aaaaRecords
		}
	}()

	go func() {
		defer wg.Done()
		if nsRecords, err := r.queryNS(ctx, name); err == nil {
			d.NS = nsRecords
		}
	}()

	wg.Wait()
	d.Resolved = true
	return nil
}

func (r *Resolver) IsCNAMETargetNXDomain(ctx context.Context, target string) (bool, error) {
	target = dns.Fqdn(target)
	msg := new(dns.Msg)
	msg.SetQuestion(target, dns.TypeA)

	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return false, err
	}

	return resp.Rcode == dns.RcodeNameError, nil
}

func (r *Resolver) HasSOAOnNS(ctx context.Context, domainName string, nameserver string) (bool, error) {
	nsIP, err := r.resolveToIP(ctx, nameserver)
	if err != nil {
		return false, err
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domainName), dns.TypeSOA)

	c := &dns.Client{Timeout: r.timeout}
	resp, _, err := c.ExchangeContext(ctx, msg, net.JoinHostPort(nsIP, "53"))
	if err != nil {
		return false, nil
	}

	for _, rr := range resp.Answer {
		if _, ok := rr.(*dns.SOA); ok {
			return true, nil
		}
	}
	for _, rr := range resp.Ns {
		if _, ok := rr.(*dns.SOA); ok {
			return true, nil
		}
	}

	return false, nil
}

func (r *Resolver) DetectWildcard(ctx context.Context, parentDomain string) bool {
	random := fmt.Sprintf("dnsdrift-wildcard-check-%d.%s", rand.Int63(), parentDomain)
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(random), dns.TypeA)

	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return false
	}

	return resp.Rcode == dns.RcodeSuccess && len(resp.Answer) > 0
}

func (r *Resolver) exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{
		Timeout: r.timeout,
		Net:     "udp",
	}

	var lastErr error
	for attempt := 0; attempt <= r.retries; attempt++ {
		server := r.nextResolver()
		resp, _, err := c.ExchangeContext(ctx, msg, server)
		if err != nil {
			lastErr = err
			if attempt == r.retries {
				c.Net = "tcp"
				resp, _, err = c.ExchangeContext(ctx, msg, server)
				if err == nil {
					return resp, nil
				}
				lastErr = err
			}
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("DNS query failed after %d attempts: %w", r.retries+1, lastErr)
}

func (r *Resolver) queryCNAME(ctx context.Context, name string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeCNAME)

	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	var cnames []string
	for _, rr := range resp.Answer {
		if cn, ok := rr.(*dns.CNAME); ok {
			target := strings.TrimSuffix(strings.ToLower(cn.Target), ".")
			cnames = append(cnames, target)
		}
	}
	return cnames, nil
}

func (r *Resolver) queryA(ctx context.Context, name string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeA)

	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			records = append(records, a.A.String())
		}
	}
	return records, nil
}

func (r *Resolver) queryAAAA(ctx context.Context, name string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeAAAA)

	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.AAAA); ok {
			records = append(records, a.AAAA.String())
		}
	}
	return records, nil
}

func (r *Resolver) queryNS(ctx context.Context, name string) ([]string, error) {
	msg := new(dns.Msg)
	msg.SetQuestion(name, dns.TypeNS)

	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return nil, err
	}

	var records []string
	for _, rr := range resp.Answer {
		if ns, ok := rr.(*dns.NS); ok {
			target := strings.TrimSuffix(strings.ToLower(ns.Ns), ".")
			records = append(records, target)
		}
	}
	return records, nil
}

func (r *Resolver) resolveToIP(ctx context.Context, hostname string) (string, error) {
	if net.ParseIP(hostname) != nil {
		return hostname, nil
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)

	resp, err := r.exchange(ctx, msg)
	if err != nil {
		return "", err
	}

	for _, rr := range resp.Answer {
		if a, ok := rr.(*dns.A); ok {
			return a.A.String(), nil
		}
	}
	return "", fmt.Errorf("could not resolve %s to IP", hostname)
}

func loadResolvers(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening resolver file: %w", err)
	}
	defer f.Close()

	var resolvers []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !strings.Contains(line, ":") {
			line = line + ":53"
		}
		resolvers = append(resolvers, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading resolver file: %w", err)
	}

	return resolvers, nil
}

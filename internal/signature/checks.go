package signature

import (
	"context"
	"strings"

	"github.com/prdp1137/dnsdrift/internal/domain"
	"github.com/prdp1137/dnsdrift/internal/httpclient"
	"github.com/prdp1137/dnsdrift/internal/resolver"
)

func (s *SignatureDef) Check(ctx context.Context, d *domain.Domain, res *resolver.Resolver, client *httpclient.Client) (bool, error) {
	switch s.Type {
	case "cname_string_in_body", "cname_or_ip_string_in_body", "ip_string_in_body":
		return checkStringInBody(ctx, d, s.Fingerprint, s.HTTPS, s.URI, client)
	case "cname_nxdomain":
		return checkCNAMENXDomain(ctx, d, res)
	case "cname_status_code":
		return checkStatusCode(ctx, d, s.StatusCode, s.HTTPS, client)
	case "ns_no_soa":
		return checkNSNoSOA(ctx, d, res)
	case "generic_cname_unregistered":
		return checkCNAMEUnregistered(ctx, d)
	case "generic_cname_nxdomain":
		return checkCNAMENXDomain(ctx, d, res)
	case "generic_cname_404":
		return checkStatusCode(ctx, d, 404, s.HTTPS, client)
	case "generic_ns_no_soa":
		return checkNSNoSOA(ctx, d, res)
	}
	return false, nil
}

func checkStringInBody(ctx context.Context, d *domain.Domain, fingerprint string, https bool, uri string, client *httpclient.Client) (bool, error) {
	url := httpclient.BuildURL(d.Name, https, uri)
	resp, err := client.Get(ctx, url)
	if err != nil {
		if https {
			url = httpclient.BuildURL(d.Name, false, uri)
			resp, err = client.Get(ctx, url)
			if err != nil {
				return false, nil
			}
		} else {
			return false, nil
		}
	}
	return strings.Contains(resp.Body, fingerprint), nil
}

func checkCNAMENXDomain(ctx context.Context, d *domain.Domain, res *resolver.Resolver) (bool, error) {
	target := d.CNAMETarget()
	if target == "" {
		return false, nil
	}
	return res.IsCNAMETargetNXDomain(ctx, target)
}

func checkStatusCode(ctx context.Context, d *domain.Domain, code int, https bool, client *httpclient.Client) (bool, error) {
	url := httpclient.BuildURL(d.Name, https, "")
	resp, err := client.Get(ctx, url)
	if err != nil {
		if code == 0 {
			return true, nil
		}
		return false, nil
	}
	return resp.StatusCode == code, nil
}

func checkNSNoSOA(ctx context.Context, d *domain.Domain, res *resolver.Resolver) (bool, error) {
	if len(d.NS) == 0 {
		return false, nil
	}

	for _, ns := range d.NS {
		hasSOA, err := res.HasSOAOnNS(ctx, d.Name, ns)
		if err != nil {
			continue
		}
		if hasSOA {
			return false, nil
		}
	}
	return true, nil
}

func checkCNAMEUnregistered(ctx context.Context, d *domain.Domain) (bool, error) {
	target := d.CNAMETarget()
	if target == "" {
		return false, nil
	}

	result, err := whoisLookup(target)
	if err != nil {
		return false, nil
	}

	unregisteredIndicators := []string{
		"No match for",
		"NOT FOUND",
		"No Data Found",
		"Domain not found",
		"No entries found",
		"Status: AVAILABLE",
		"is free",
	}

	for _, indicator := range unregisteredIndicators {
		if strings.Contains(result, indicator) {
			return true, nil
		}
	}

	return false, nil
}

var whoisLookup = defaultWhoisLookup

func defaultWhoisLookup(domain string) (string, error) {
	return whoisQuery(domain)
}

package signature

import (
	"strings"

	"github.com/prdp1137/dnsdrift/internal/domain"
)

var cnameNXDomainExclusions = []string{
	// AWS (ELB, CloudFront — not claimable)
	"elb.amazonaws.com",
	".cloudfront.net",

	// CDN / WAF — managed infrastructure, no self-service claim
	".edgekey.net",
	".akamai.net",
	".akamaiedge.net",
	".impervadns.net",
	".incapdns.net",
	".cdngslb.com",
	".aliyuncs.com",
	".fastly.net",
	".fastlylb.net",

	// Email / marketing — domain verification required
	".sendgrid.net",
	".pardot.com",
	".en25.com",

	// SaaS — not vulnerable per can-i-take-over-xyz
	".zendesk.com",
	".firebaseapp.com",
	".hubspot.net",
	".squarespace.com",

	// Corporate / legacy — not self-service platforms
	".yahoo.com",
	".yahoodns.net",
	".oath.cloud",
	".dailymotion.com",
	".swisscom.com",
	".microsoft.com",
	".svc.domains",
	".oracle.com",

	// Other
	".invalid",
	"online.lync.com",
}

// NS providers that are NOT exploitable (require account verification or
// contractual onboarding to create zones).
var nsExclusions = []string{
	"awsdns",       // AWS Route53 — zone creation requires account ownership
	".cloudflare.", // Cloudflare — requires account domain verification
	"akam.net",     // Akamai — contractual onboarding
	".dailymotion.",
	".swisscom.",
}

func (s *SignatureDef) Potential(d *domain.Domain) bool {
	switch s.Type {
	case "cname_string_in_body":
		return matchAnyCNAME(d, s.Cnames)
	case "cname_or_ip_string_in_body":
		return matchAnyCNAME(d, s.Cnames) || matchAnyIP(d, s.IPs)
	case "ip_string_in_body":
		return matchAnyIP(d, s.IPs)
	case "cname_nxdomain":
		return matchAnyCNAME(d, s.Cnames)
	case "cname_status_code":
		return matchAnyCNAME(d, s.Cnames)
	case "ns_no_soa":
		return matchAnyNS(d, s.Nameservers)
	case "generic_cname_unregistered":
		return d.IsExternalCNAME() && d.IsTwoPartCNAME()
	case "generic_cname_nxdomain":
		return hasFilteredExternalCNAME(d)
	case "generic_cname_404":
		return d.IsExternalCNAME()
	case "generic_ns_no_soa":
		return hasExternalNS(d)
	}
	return false
}

func matchAnyCNAME(d *domain.Domain, patterns []string) bool {
	for _, p := range patterns {
		if d.HasCNAME(p) {
			return true
		}
	}
	return false
}

func matchAnyIP(d *domain.Domain, ips []string) bool {
	for _, ip := range ips {
		if d.HasIP(ip) {
			return true
		}
	}
	return false
}

func matchAnyNS(d *domain.Domain, patterns []string) bool {
	for _, p := range patterns {
		if d.HasNS(p) {
			return true
		}
	}
	return false
}

func hasFilteredExternalCNAME(d *domain.Domain) bool {
	if !d.IsExternalCNAME() {
		return false
	}
	target := strings.ToLower(d.CNAMETarget())
	for _, excl := range cnameNXDomainExclusions {
		if strings.HasSuffix(target, excl) {
			return false
		}
	}
	return true
}

func hasExternalNS(d *domain.Domain) bool {
	srcReg := registeredDomainFromNS(d.Name)
	for _, ns := range d.NS {
		nsReg := registeredDomainFromNS(ns)
		if srcReg != "" && nsReg != "" && srcReg != nsReg {
			nsLower := strings.ToLower(ns)
			excluded := false
			for _, excl := range nsExclusions {
				if strings.Contains(nsLower, excl) {
					excluded = true
					break
				}
			}
			if !excluded {
				return true
			}
		}
	}
	return false
}

func registeredDomainFromNS(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

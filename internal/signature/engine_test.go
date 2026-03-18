package signature

import (
	"testing"

	"github.com/prdp1137/dnsdrift/internal/domain"
)

func TestPotential_CNAMEStringInBody(t *testing.T) {
	sig := &SignatureDef{
		Type:   "cname_string_in_body",
		Cnames: []string{".github.io"},
	}

	match := &domain.Domain{CNAMES: []string{"foo.github.io"}}
	noMatch := &domain.Domain{CNAMES: []string{"foo.herokuapp.com"}}

	if !sig.Potential(match) {
		t.Error("should match .github.io CNAME")
	}
	if sig.Potential(noMatch) {
		t.Error("should not match .herokuapp.com")
	}
}

func TestPotential_CNAMEOrIPStringInBody(t *testing.T) {
	sig := &SignatureDef{
		Type:   "cname_or_ip_string_in_body",
		Cnames: []string{".github.io"},
		IPs:    []string{"185.199.108.153"},
	}

	byCNAME := &domain.Domain{CNAMES: []string{"foo.github.io"}}
	byIP := &domain.Domain{A: []string{"185.199.108.153"}}
	neither := &domain.Domain{A: []string{"1.2.3.4"}}

	if !sig.Potential(byCNAME) {
		t.Error("should match by CNAME")
	}
	if !sig.Potential(byIP) {
		t.Error("should match by IP")
	}
	if sig.Potential(neither) {
		t.Error("should not match")
	}
}

func TestPotential_NSNoSOA(t *testing.T) {
	sig := &SignatureDef{
		Type:        "ns_no_soa",
		Nameservers: []string{"ns1.digitalocean.com"},
	}

	match := &domain.Domain{NS: []string{"ns1.digitalocean.com", "ns2.digitalocean.com"}}
	noMatch := &domain.Domain{NS: []string{"ns1.cloudflare.com"}}

	if !sig.Potential(match) {
		t.Error("should match digitalocean NS")
	}
	if sig.Potential(noMatch) {
		t.Error("should not match cloudflare NS")
	}
}

func TestPotential_GenericCNAMENXDomain(t *testing.T) {
	sig := &SignatureDef{Type: "generic_cname_nxdomain"}

	// External CNAME, not excluded
	match := &domain.Domain{
		Name:   "app.example.com",
		CNAMES: []string{"target.otherdomain.com"},
	}
	if !sig.Potential(match) {
		t.Error("should match external CNAME")
	}

	// Excluded suffix
	excluded := &domain.Domain{
		Name:   "app.example.com",
		CNAMES: []string{"thing.cloudfront.net"},
	}
	if sig.Potential(excluded) {
		t.Error("should not match excluded .cloudfront.net")
	}

	// Internal CNAME
	internal := &domain.Domain{
		Name:   "app.example.com",
		CNAMES: []string{"www.example.com"},
	}
	if sig.Potential(internal) {
		t.Error("should not match internal CNAME")
	}
}

func TestPotential_GenericCNAMEUnregistered(t *testing.T) {
	sig := &SignatureDef{Type: "generic_cname_unregistered"}

	// External two-part CNAME
	match := &domain.Domain{
		Name:   "app.example.com",
		CNAMES: []string{"orphaned.xyz"},
	}
	if !sig.Potential(match) {
		t.Error("should match external two-part CNAME")
	}

	// Three-part CNAME (not two-part)
	threePart := &domain.Domain{
		Name:   "app.example.com",
		CNAMES: []string{"sub.other.com"},
	}
	if sig.Potential(threePart) {
		t.Error("should not match three-part CNAME")
	}
}

func TestPotential_GenericNSNoSOA(t *testing.T) {
	sig := &SignatureDef{Type: "generic_ns_no_soa"}

	external := &domain.Domain{
		Name: "sub.example.com",
		NS:   []string{"ns1.otherprovider.com"},
	}
	if !sig.Potential(external) {
		t.Error("should match external NS")
	}

	internal := &domain.Domain{
		Name: "sub.example.com",
		NS:   []string{"ns1.example.com"},
	}
	if sig.Potential(internal) {
		t.Error("should not match internal NS")
	}
}

func TestLoadSignatures(t *testing.T) {
	sigs, err := LoadSignatures("")
	if err != nil {
		t.Fatalf("LoadSignatures: %v", err)
	}
	if len(sigs) < 40 {
		t.Errorf("expected at least 40 signatures, got %d", len(sigs))
	}

	// Check a known signature
	var found bool
	for _, s := range sigs {
		if s.Name == "github_pages" {
			found = true
			if s.Type != "cname_or_ip_string_in_body" {
				t.Errorf("github_pages type = %q, want cname_or_ip_string_in_body", s.Type)
			}
			if s.Confidence != Confirmed {
				t.Errorf("github_pages confidence = %q, want confirmed", s.Confidence)
			}
			break
		}
	}
	if !found {
		t.Error("github_pages signature not found")
	}
}

func TestGenerateInfo(t *testing.T) {
	// Custom info
	sig := &SignatureDef{Info: "custom info"}
	if got := sig.GenerateInfo(); got != "custom info" {
		t.Errorf("GenerateInfo() = %q, want %q", got, "custom info")
	}

	// Auto-generated
	sig2 := &SignatureDef{Type: "cname_string_in_body", Service: "GitHub Pages"}
	info := sig2.GenerateInfo()
	if info == "" {
		t.Error("GenerateInfo() should not be empty for auto-generated")
	}
}

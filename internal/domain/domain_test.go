package domain

import "testing"

func TestHasCNAME(t *testing.T) {
	d := &Domain{
		CNAMES: []string{"foo.github.io", "bar.netlify.app"},
	}

	tests := []struct {
		pattern string
		want    bool
	}{
		{".github.io", true},
		{".netlify.app", true},
		{".herokuapp.com", false},
		{"github.io", true},
		{"GITHUB.IO", true}, // case insensitive
	}

	for _, tt := range tests {
		if got := d.HasCNAME(tt.pattern); got != tt.want {
			t.Errorf("HasCNAME(%q) = %v, want %v", tt.pattern, got, tt.want)
		}
	}
}

func TestHasIP(t *testing.T) {
	d := &Domain{
		A:    []string{"185.199.108.153"},
		AAAA: []string{"2606:50c0:8000::153"},
	}

	tests := []struct {
		ip   string
		want bool
	}{
		{"185.199.108.153", true},
		{"2606:50c0:8000::153", true},
		{"1.2.3.4", false},
	}

	for _, tt := range tests {
		if got := d.HasIP(tt.ip); got != tt.want {
			t.Errorf("HasIP(%q) = %v, want %v", tt.ip, got, tt.want)
		}
	}
}

func TestHasNS(t *testing.T) {
	d := &Domain{
		NS: []string{"ns1.digitalocean.com", "ns2.digitalocean.com"},
	}

	if !d.HasNS("digitalocean.com") {
		t.Error("HasNS should match digitalocean.com")
	}
	if d.HasNS("cloudflare.com") {
		t.Error("HasNS should not match cloudflare.com")
	}
}

func TestCNAMETarget(t *testing.T) {
	d := &Domain{CNAMES: []string{"first.example.com", "final.target.com"}}
	if got := d.CNAMETarget(); got != "final.target.com" {
		t.Errorf("CNAMETarget() = %q, want %q", got, "final.target.com")
	}

	empty := &Domain{}
	if got := empty.CNAMETarget(); got != "" {
		t.Errorf("CNAMETarget() on empty = %q, want empty", got)
	}
}

func TestIsExternalCNAME(t *testing.T) {
	tests := []struct {
		name   string
		domain Domain
		want   bool
	}{
		{
			"external CNAME",
			Domain{Name: "app.example.com", CNAMES: []string{"app.github.io"}},
			true,
		},
		{
			"internal CNAME",
			Domain{Name: "app.example.com", CNAMES: []string{"www.example.com"}},
			false,
		},
		{
			"no CNAME",
			Domain{Name: "example.com"},
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.domain.IsExternalCNAME(); got != tt.want {
				t.Errorf("IsExternalCNAME() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsTwoPartCNAME(t *testing.T) {
	tests := []struct {
		cnames []string
		want   bool
	}{
		{[]string{"example.com"}, true},
		{[]string{"sub.example.com"}, false},
		{[]string{"a.b.c.com"}, false},
		{nil, false},
	}

	for _, tt := range tests {
		d := &Domain{CNAMES: tt.cnames}
		if got := d.IsTwoPartCNAME(); got != tt.want {
			t.Errorf("IsTwoPartCNAME(%v) = %v, want %v", tt.cnames, got, tt.want)
		}
	}
}

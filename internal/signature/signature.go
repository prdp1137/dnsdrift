package signature

import (
	_ "embed"
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

//go:embed signatures.yaml
var embeddedSignatures []byte

type Confidence string

const (
	Confirmed  Confidence = "confirmed"
	Potential  Confidence = "potential"
	Unlikely   Confidence = "unlikely"
	Unverified Confidence = "unverified"
)

type SignatureDef struct {
	Name        string     `yaml:"name"`
	Type        string     `yaml:"type"`
	Confidence  Confidence `yaml:"confidence"`
	Service     string     `yaml:"service"`
	Cnames      []string   `yaml:"cnames,omitempty"`
	IPs         []string   `yaml:"ips,omitempty"`
	Nameservers []string   `yaml:"nameservers,omitempty"`
	Fingerprint string     `yaml:"fingerprint,omitempty"`
	StatusCode  int        `yaml:"status_code,omitempty"`
	HTTPS       bool       `yaml:"https,omitempty"`
	URI         string     `yaml:"uri,omitempty"`
	Info        string     `yaml:"info,omitempty"`
	MoreInfoURL string     `yaml:"more_info_url,omitempty"`
}

func (s *SignatureDef) GenerateInfo() string {
	if s.Info != "" {
		return s.Info
	}
	switch s.Type {
	case "cname_string_in_body", "cname_or_ip_string_in_body", "ip_string_in_body":
		return fmt.Sprintf("The domain has DNS records for %s but a web request shows it is unclaimed. An attacker can register this domain on %s.", s.Service, s.Service)
	case "cname_nxdomain":
		return fmt.Sprintf("The domain has CNAME records for %s but they do not resolve. An attacker can register this domain on %s.", s.Service, s.Service)
	case "cname_status_code":
		return fmt.Sprintf("The domain has a CNAME for %s but the website returns HTTP %d. You should investigate.", s.Service, s.StatusCode)
	case "ns_no_soa":
		return fmt.Sprintf("The domain has %s NS records but those nameservers do not host a zone for this domain. An attacker can register this domain with %s.", s.Service, s.Service)
	default:
		return fmt.Sprintf("Potential subdomain takeover via %s.", s.Service)
	}
}

func LoadSignatures(customPath string) ([]SignatureDef, error) {
	var data []byte
	if customPath != "" {
		var err error
		data, err = os.ReadFile(customPath)
		if err != nil {
			return nil, fmt.Errorf("reading custom signatures: %w", err)
		}
	} else {
		data = embeddedSignatures
	}

	var sigs []SignatureDef
	if err := yaml.Unmarshal(data, &sigs); err != nil {
		return nil, fmt.Errorf("parsing signatures YAML: %w", err)
	}
	return sigs, nil
}

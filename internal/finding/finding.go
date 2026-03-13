package finding

import "github.com/prdp1137/dnsdrift/internal/signature"

type Finding struct {
	Domain     string               `json:"domain"`
	Service    string               `json:"service"`
	Signature  string               `json:"signature"`
	Confidence signature.Confidence `json:"confidence"`
	Info       string               `json:"info"`
	CNAMES     []string             `json:"cnames,omitempty"`
	A          []string             `json:"a_records,omitempty"`
	AAAA       []string             `json:"aaaa_records,omitempty"`
	NS         []string             `json:"ns_records,omitempty"`
}

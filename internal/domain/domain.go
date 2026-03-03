package domain

import "strings"

type Domain struct {
	Name     string
	CNAMES   []string
	A        []string
	AAAA     []string
	NS       []string
	SOA      bool
	Resolved bool
}

func (d *Domain) HasCNAME(pattern string) bool {
	p := strings.ToLower(pattern)
	for _, c := range d.CNAMES {
		if strings.Contains(strings.ToLower(c), p) {
			return true
		}
	}
	return false
}

func (d *Domain) HasIP(ip string) bool {
	for _, a := range d.A {
		if a == ip {
			return true
		}
	}
	for _, a := range d.AAAA {
		if a == ip {
			return true
		}
	}
	return false
}

func (d *Domain) HasNS(pattern string) bool {
	p := strings.ToLower(pattern)
	for _, ns := range d.NS {
		if strings.Contains(strings.ToLower(ns), p) {
			return true
		}
	}
	return false
}

func (d *Domain) CNAMETarget() string {
	if len(d.CNAMES) == 0 {
		return ""
	}
	return d.CNAMES[len(d.CNAMES)-1]
}

func (d *Domain) IsExternalCNAME() bool {
	target := d.CNAMETarget()
	if target == "" {
		return false
	}
	srcReg := registeredDomain(d.Name)
	tgtReg := registeredDomain(target)
	return srcReg != "" && tgtReg != "" && srcReg != tgtReg
}

func (d *Domain) IsTwoPartCNAME() bool {
	target := d.CNAMETarget()
	if target == "" {
		return false
	}
	target = strings.TrimSuffix(target, ".")
	parts := strings.Split(target, ".")
	return len(parts) == 2
}

func registeredDomain(name string) string {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	parts := strings.Split(name, ".")
	if len(parts) < 2 {
		return name
	}
	return parts[len(parts)-2] + "." + parts[len(parts)-1]
}

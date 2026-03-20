package signature

import "github.com/likexian/whois"

func whoisQuery(domain string) (string, error) {
	return whois.Whois(domain)
}

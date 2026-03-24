# dnsdrift

Fast subdomain takeover scanner built for scale. Scans millions of subdomains concurrently, matches against 79 built-in signatures, and filters out false positives.

## Install

```bash
go install github.com/prdp1137/dnsdrift/cmd/dnsdrift@latest
```

Or build from source:

```bash
git clone https://github.com/prdp1137/dnsdrift.git
cd dnsdrift
go build -o dnsdrift ./cmd/dnsdrift/
```

## Usage

```bash
# scan from file
dnsdrift -l subdomains.txt

# single domain
dnsdrift -d sub.example.com

# pipe from subfinder
subfinder -d example.com -silent | dnsdrift

# json output, custom resolvers, 200 workers
dnsdrift -l subs.txt -r resolvers.txt -w 200 -o json > results.json
```

## Flags

```
-l string        file containing subdomains (one per line)
-d string        single domain to scan
-r string        file containing resolver IPs (one per line)
-w int           number of concurrent workers (default 100)
-timeout int     timeout per request in seconds (default 10)
-rate-limit int  max domains per second, 0 = unlimited (default 0)
-signatures str  custom signatures YAML file (overrides built-in)
-o string        output format: table or json (default "table")
-progress        show progress on stderr (default true)
-version         print version and exit
```

## How It Works

1. Reads domains from file, flag, or stdin (deduplicates automatically)
2. Resolves DNS records in parallel (CNAME, A, AAAA, NS) using worker pool
3. Matches each domain against signature database (pre-filter + verification)
4. Outputs findings ranked by confidence level

## Signatures

79 signatures sourced from [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz), [can-i-take-over-dns](https://github.com/indianajson/can-i-take-over-dns), and [dnsReaper](https://github.com/punk-security/dnsReaper).

| Type | Count | How it detects |
|------|-------|----------------|
| CNAME + body fingerprint | 53 | CNAME matches known service, HTTP body contains error string |
| CNAME + NXDOMAIN | 3 | CNAME points to service that returns NXDOMAIN |
| CNAME + status code | 5 | CNAME matches, HTTP returns specific status code |
| IP + body fingerprint | 2 | A record matches, HTTP body contains error string |
| NS + no SOA | 11 | NS delegates to provider that has no zone for domain |
| Generic detections | 5 | Catch-all for unregistered CNAMEs, dangling records, external 404s |

### Covered Services

AWS S3, Azure (16 patterns), Elastic Beanstalk (29 regions), GitHub Pages, Heroku, Netlify, Vercel, Shopify, Webflow, Wix, Ghost, Bitbucket, Pantheon, Strikingly, ReadTheDocs, Readme.io, Intercom, UserVoice, Canny, Kinsta, and 50+ more.

### Confidence Levels

- `confirmed` - signature matched and verified, high likelihood of takeover
- `potential` - pattern matches but needs manual verification
- `unlikely` - weak signal, probably not exploitable

## Output

**Table** (default):

```
DOMAIN                              SERVICE              CONFIDENCE  INFO
────────────────────────────────────────────────────────────────────────────
dev.example.com                     AWS S3               confirmed   NoSuchBucket
blog.example.com                    Github Pages         potential   There isn't a GitHub Pages site here.
```

**JSON** (`-o json`):

```json
[
  {
    "domain": "dev.example.com",
    "service": "AWS S3",
    "signature": "aws_s3",
    "confidence": "confirmed",
    "info": "...",
    "cnames": ["dev.example.com.s3.amazonaws.com"],
    "a": [],
    "aaaa": [],
    "ns": []
  }
]
```

## Custom Signatures

Create a YAML file and pass it with `-signatures`:

```yaml
- name: my_service
  type: cname_string_in_body
  confidence: confirmed
  service: My Service
  cnames: [".myservice.com"]
  fingerprint: "This site is not configured"
```

Signature types: `cname_string_in_body`, `cname_or_ip_string_in_body`, `ip_string_in_body`, `cname_nxdomain`, `cname_status_code`, `ns_no_soa`.

## Performance

- Default 100 workers, tested with higher concurrency on large lists
- Rate limiting available for targets that throttle
- Round-robin resolver distribution across custom resolver list
- UDP with TCP fallback, 2 retries per query
- 1 MB response body cap to prevent memory issues

## License

MIT

# S4YEM.7KuroX — Bug Bounty Recon Command Handbook (2026)

**Created by Sayem Hossain | S4YEM.7KuroX**  
*Command-focused reference for authorized bug bounty and web application security testing.*

> Replace `target.com` and example URLs with assets explicitly included in your program scope. A related domain, IP, ASN, cloud bucket, or third-party service is not automatically authorized. Check the program policy and rate limits before active testing.

---

## 0. Setup and workspace

```bash
export TARGET="target.com"
export ROOT="https://${TARGET}"
export DNS_WORDLIST="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
export WEB_WORDLIST="/usr/share/seclists/Discovery/Web-Content/common.txt"

mkdir -p "$TARGET"/{subs,dns,ips,web,urls,js,content,ports,nuclei,screenshots,notes,reports}
cd "$TARGET"

# Check installed tools
for t in subfinder assetfinder amass findomain dnsx httpx katana gau waybackurls \
         uro anew jq curl dig whois ffuf arjun nuclei nmap; do
  command -v "$t" >/dev/null 2>&1 && printf '[OK] %s\n' "$t" || printf '[MISSING] %s\n' "$t"
done
```

## 1. Passive subdomain enumeration

```bash
subfinder -d "$TARGET" -silent -o subs/subfinder.txt
assetfinder --subs-only "$TARGET" > subs/assetfinder.txt
amass enum -passive -d "$TARGET" -o subs/amass-passive.txt
findomain -t "$TARGET" -u subs/findomain.txt

# Certificate Transparency
curl -s "https://crt.sh/?q=%25.${TARGET}&output=json" \
  | jq -r '.[].name_value' | tr ',' '\n' | sed 's/^\*\.//' \
  | grep -E "(^|\\.)${TARGET//./\\.}$" | sort -u > subs/crtsh.txt

# Merge + deduplicate
cat subs/*.txt 2>/dev/null | sed 's/^\*\.//' | sort -u > subs/all.txt
wc -l subs/all.txt
```

## 2. Active DNS discovery (only if permitted)

```bash
# DNS brute-force
dnsx -d "$TARGET" -w "$DNS_WORDLIST" -silent -o dns/bruteforce.txt

# Resolve discovered names
dnsx -l subs/all.txt -silent -a -resp -o dns/resolved.txt

# CNAMEs
dnsx -l subs/all.txt -silent -cname -resp -o dns/cnames.txt

# Wildcard check / spot-check
dig "random-check-93824.${TARGET}" A +short
dig "$TARGET" NS +short
dig "$TARGET" MX +short
```

## 3. Permutation and candidate expansion

```bash
# Gotator syntax varies by version; check gotator -h first
gotator -sub subs/all.txt -perm /path/to/permutations.txt -depth 1 \
  | sort -u > subs/permutations.txt

dnsx -l subs/permutations.txt -silent -a -resp -o dns/permutations-resolved.txt
```

Do not scan every guessed name blindly. Validate scope and keep request rates conservative.

## 4. Live HTTP services and technology fingerprinting

```bash
# Probe web services
httpx -l subs/all.txt -silent -o web/live.txt

# Metadata
httpx -l subs/all.txt -silent -status-code -title -tech-detect \
  -web-server -content-length -follow-redirects -o web/live-metadata.txt

# Extract status-code subsets from saved metadata
grep '\[200\]' web/live-metadata.txt > web/status-200.txt
grep '\[403\]' web/live-metadata.txt > web/status-403.txt
grep '\[401\]' web/live-metadata.txt > web/status-401.txt

# Fingerprinting
whatweb -i web/live.txt --log-brief=web/whatweb.txt
```

## 5. URL collection: historical + crawling

```bash
# Wayback
cat web/live.txt | waybackurls | sort -u > urls/wayback.txt

# GAU
cat web/live.txt | gau --threads 5 | sort -u > urls/gau.txt

# Katana crawler — use low concurrency on production targets
katana -list web/live.txt -d 3 -jc -silent -o urls/katana.txt

# Merge
cat urls/wayback.txt urls/gau.txt urls/katana.txt 2>/dev/null \
  | sort -u > urls/all.txt

wc -l urls/all.txt
```

## 6. URL triage filters

```bash
# JavaScript
grep -Ei '\.js([?#]|$)' urls/all.txt | grep -Eiv '\.json([?#]|$)' \
  | sort -u > urls/js.txt

# API / GraphQL candidates
grep -Ei 'api|graphql|/v[0-9]+/|\.json([?#]|$)' urls/all.txt \
  | sort -u > urls/api-candidates.txt

# Authentication / account flows
grep -Ei 'login|signin|logout|auth|oauth|callback|reset|password|session|mfa|sso' \
  urls/all.txt | sort -u > urls/auth.txt

# Upload / download / import / export
grep -Ei 'upload|download|import|export|attachment|media|file' \
  urls/all.txt | sort -u > urls/files.txt

# Admin / debug / internal candidates
grep -Ei 'admin|dashboard|manage|internal|debug|trace|actuator|swagger|openapi' \
  urls/all.txt | sort -u > urls/admin-debug.txt

# Redirect candidates
grep -Ei 'redirect|returnUrl|return_url|continue|callback|next=|dest=|url=' \
  urls/all.txt | sort -u > urls/redirects.txt

# Parameterized URLs
grep '=' urls/all.txt | sort -u > urls/parameterized.txt

# Common backend extensions
grep -Ei '\.(php|aspx?|jsp|do|action)([?#]|$)' urls/all.txt \
  | sort -u > urls/backend.txt

# Potentially sensitive file names/extensions: inspect manually; do not mass-download
grep -Ei '\.(env|bak|backup|old|sql|db|log|conf|config|yaml|yml|pem|key|zip|tar|gz)([?#]|$)' \
  urls/all.txt | sort -u > urls/sensitive-candidates.txt
```

## 7. Parameter discovery

```bash
# Arjun: single endpoint (review arjun -h for version-specific options)
arjun -u "${ROOT}/example" -m GET

# ParamSpider: archived parameterized URLs
paramspider -d "$TARGET"

# Clean parameter values to compare URL shapes
sed -E 's/=[^&]*/=/g' urls/parameterized.txt | sort -u > urls/parameter-names.txt
```

Treat discovered parameters as hypotheses. Verify their behavior in a proxy using your own test account and non-destructive values.

## 8. JavaScript collection and review

```bash
# Extract JS URLs from URL corpus
cat urls/js.txt | sort -u > js/js-urls.txt

# Download in-scope JavaScript files for local review (simple example)
mkdir -p js/downloaded
while IFS= read -r u; do
  name=$(printf '%s' "$u" | sha256sum | cut -d' ' -f1)
  curl -fsSL --max-time 15 "$u" -o "js/downloaded/${name}.js" || true
done < js/js-urls.txt

# Search for route names / suspicious strings (manual review required)
grep -RniE 'api[_-]?key|client[_-]?secret|access[_-]?token|password|graphql|internal|debug|swagger' \
  js/downloaded/ > js/string-hits.txt 2>/dev/null
```

Do not use found tokens or credentials. Report suspected exposures with minimal redacted evidence and follow the program's rules.

## 9. Content discovery (rate-limited)

```bash
# Small wordlist first; use only where content discovery is allowed
ffuf -u "${ROOT}/FUZZ" -w "$WEB_WORDLIST" \
  -rate 5 -mc 200,204,301,302,307,401,403 \
  -of json -o content/ffuf.json
```

Do not assume `200`, `401`, or `403` means a vulnerability. Check response body, redirects, content type, and intended access controls.

## 10. Screenshots

```bash
# Example for gowitness versions that support file input
gowitness file -f web/live.txt -P screenshots/
```

Check `gowitness --help` if the installed version uses different syntax.

## 11. DNS / IP / ASN context

```bash
# DNS records for an in-scope host
dig "$TARGET" A +short
dig "$TARGET" AAAA +short
dig "$TARGET" CNAME +short
dig "$TARGET" NS +short
dig "$TARGET" MX +short
dig "$TARGET" TXT +short

# WHOIS context
whois "$TARGET"

# Public ASN lookup (manual research)
# https://bgp.tools/
# https://bgp.he.net/
```

Do not convert an organization's ASN/CIDR into a scan target unless that range is explicitly included in scope.

## 12. Port and service checks — explicit authorization required

```bash
# Only for a specifically authorized host
nmap -sV --top-ports 100 -T2 -oN ports/nmap-top100.txt target.example
```

Avoid broad IP-range scans, full-port scans, intrusive scripts, or scanning shared hosting without explicit permission.

## 13. Nuclei — candidate detection only

```bash
# Low-rate scan on one authorized web host; verify current flags with nuclei -h
nuclei -u "$ROOT" -rl 2 -severity medium,high,critical \
  -o nuclei/candidates.txt
```

Scanner findings require manual validation. Do not use proxy rotation or spoofed client-IP headers to evade controls, and do not run intrusive templates unless explicitly allowed.

## 14. Subdomain takeover triage

```bash
# Collect CNAMEs for review
dnsx -l subs/all.txt -silent -cname -resp -o dns/cnames.txt
```

A dangling CNAME is only a lead. Do not register, claim, or modify a third-party resource. Verify provider-specific indicators and report the candidate safely.

## 15. Handy shell commands

```bash
# Count lines
wc -l subs/all.txt urls/all.txt

# Sort unique
sort -u input.txt > output.txt

# Remove blank lines and CRLF
sed -i 's/\r$/' input.txt
grep -v '^[[:space:]]*$' input.txt > cleaned.txt

# Check duplicates
sort input.txt | uniq -d

# Count HTTP status codes in a metadata file (adapt to output format)
grep -oE '\[[0-9]{3}\]' web/live-metadata.txt | sort | uniq -c | sort -nr

# Search for a keyword in notes
grep -RniE 'idor|oauth|session|authorization|business logic' notes/
```

## References

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP API Security: https://owasp.org/www-project-api-security/
- PortSwigger Web Security Academy: https://portswigger.net/web-security

## Changelog

- **2026-10-18:** Command-focused recon handbook edition created by Sayem Hossain (`S4YEM.7KuroX`).

## License

Add a license before publishing. If adapting content from another repository, review its license and preserve required attribution.

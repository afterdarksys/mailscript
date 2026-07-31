package authverify

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

const maxMTASTSPolicyBytes = 64 << 10

// TLSReportPolicy is the parsed _smtp._tls record from RFC 8460.
type TLSReportPolicy struct {
	Result      string
	Domain      string
	Record      string
	ReportURIs  []string
	DNSSEC      bool
	Explanation string
}

// MTASTSPolicy is the DNS discovery record and HTTPS policy from RFC 8461.
type MTASTSPolicy struct {
	Result      string
	Domain      string
	ID          string
	Mode        string
	MX          []string
	MaxAge      int
	DNSSEC      bool
	Explanation string
}

// PolicyFetcher retrieves the MTA-STS HTTPS policy. Tests can supply a
// deterministic fetcher; nil uses an HTTPS-only client with bounded I/O.
type PolicyFetcher func(ctx context.Context, policyURL string) ([]byte, error)

// CheckTLSReporting discovers and parses a TLS-RPT policy.
func CheckTLSReporting(resolver *dnsx.Resolver, domain string) TLSReportPolicy {
	domain = normalizePolicyDomain(domain)
	out := TLSReportPolicy{Domain: domain, Result: "none"}
	if domain == "" || !resolver.Enabled() {
		out.Result = "temperror"
		out.Explanation = "no DNS resolver configured"
		return out
	}
	answer := resolver.LookupTXTAuthenticated("_smtp._tls." + domain)
	out.DNSSEC = answer.Secure
	if answer.Error != "" {
		out.Result = "temperror"
		out.Explanation = answer.Error
		return out
	}
	var candidates []string
	for _, record := range answer.Records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=tlsrptv1") {
			candidates = append(candidates, record)
		}
	}
	if len(candidates) == 0 {
		out.Explanation = "no TLS-RPT record published"
		return out
	}
	if len(candidates) != 1 {
		out.Result = "permerror"
		out.Explanation = "multiple TLS-RPT records published"
		return out
	}
	out.Record = candidates[0]
	tags := parsePolicyTags(out.Record)
	if !strings.EqualFold(tags["v"], "TLSRPTv1") || tags["rua"] == "" {
		out.Result = "permerror"
		out.Explanation = "TLS-RPT record must contain v=TLSRPTv1 and rua="
		return out
	}
	for _, rawURI := range strings.Split(tags["rua"], ",") {
		rawURI = strings.TrimSpace(rawURI)
		u, err := url.Parse(rawURI)
		if err != nil || (u.Scheme != "mailto" && u.Scheme != "https") || u.String() == "" {
			out.Result = "permerror"
			out.Explanation = fmt.Sprintf("invalid TLS-RPT report URI %q", rawURI)
			return out
		}
		out.ReportURIs = append(out.ReportURIs, rawURI)
	}
	out.Result = "valid"
	out.Explanation = fmt.Sprintf("TLS-RPT sends aggregate reports to %d URI(s)", len(out.ReportURIs))
	return out
}

// CheckMTASTS discovers the MTA-STS version identifier in DNS and retrieves
// the authenticated HTTPS policy from mta-sts.<domain>.
func CheckMTASTS(resolver *dnsx.Resolver, domain string, fetch PolicyFetcher) MTASTSPolicy {
	domain = normalizePolicyDomain(domain)
	out := MTASTSPolicy{Domain: domain, Result: "none"}
	if domain == "" || !resolver.Enabled() {
		out.Result = "temperror"
		out.Explanation = "no DNS resolver configured"
		return out
	}
	answer := resolver.LookupTXTAuthenticated("_mta-sts." + domain)
	out.DNSSEC = answer.Secure
	if answer.Error != "" {
		out.Result = "temperror"
		out.Explanation = answer.Error
		return out
	}
	var candidates []string
	for _, record := range answer.Records {
		if strings.HasPrefix(strings.ToLower(strings.TrimSpace(record)), "v=stsv1") {
			candidates = append(candidates, record)
		}
	}
	if len(candidates) == 0 {
		out.Explanation = "no MTA-STS record published"
		return out
	}
	if len(candidates) != 1 {
		out.Result = "permerror"
		out.Explanation = "multiple MTA-STS records published"
		return out
	}
	tags := parsePolicyTags(candidates[0])
	out.ID = strings.TrimSpace(tags["id"])
	if !strings.EqualFold(tags["v"], "STSv1") || out.ID == "" {
		out.Result = "permerror"
		out.Explanation = "MTA-STS DNS record must contain v=STSv1 and a non-empty id="
		return out
	}
	if fetch == nil {
		fetch = defaultPolicyFetcher
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	body, err := fetch(ctx, "https://mta-sts."+domain+"/.well-known/mta-sts.txt")
	if err != nil {
		out.Result = "temperror"
		out.Explanation = "MTA-STS policy fetch failed: " + err.Error()
		return out
	}
	if err := parseMTASTSPolicy(body, &out); err != nil {
		out.Result = "permerror"
		out.Explanation = err.Error()
		return out
	}
	out.Result = "valid"
	out.Explanation = fmt.Sprintf("MTA-STS policy mode=%s covers %d MX pattern(s)", out.Mode, len(out.MX))
	return out
}

func defaultPolicyFetcher(ctx context.Context, policyURL string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, policyURL, nil)
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		addresses, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, address := range addresses {
			ip := address.IP
			if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
				continue
			}
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
		}
		return nil, fmt.Errorf("MTA-STS host resolved only to private or non-routable addresses")
	}}
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
		return fmt.Errorf("redirects are not permitted for MTA-STS policies")
	}}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTPS status %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxMTASTSPolicyBytes+1))
}

func parseMTASTSPolicy(body []byte, out *MTASTSPolicy) error {
	if len(body) > maxMTASTSPolicyBytes {
		return fmt.Errorf("MTA-STS policy exceeds %d bytes", maxMTASTSPolicyBytes)
	}
	fields := map[string][]string{}
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			return fmt.Errorf("malformed MTA-STS policy line %q", line)
		}
		key := strings.ToLower(strings.TrimSpace(parts[0]))
		fields[key] = append(fields[key], strings.TrimSpace(parts[1]))
	}
	if len(fields["version"]) != 1 || fields["version"][0] != "STSv1" {
		return fmt.Errorf("MTA-STS policy must contain exactly one version: STSv1")
	}
	if len(fields["mode"]) != 1 {
		return fmt.Errorf("MTA-STS policy must contain exactly one mode")
	}
	out.Mode = strings.ToLower(fields["mode"][0])
	if out.Mode != "none" && out.Mode != "testing" && out.Mode != "enforce" {
		return fmt.Errorf("invalid MTA-STS mode %q", out.Mode)
	}
	out.MX = append([]string(nil), fields["mx"]...)
	if out.Mode != "none" && len(out.MX) == 0 {
		return fmt.Errorf("MTA-STS %s policy requires at least one mx entry", out.Mode)
	}
	for _, pattern := range out.MX {
		name := pattern
		if strings.HasPrefix(name, "*.") {
			name = strings.TrimPrefix(name, "*.")
		} else if strings.Contains(name, "*") {
			return fmt.Errorf("invalid MTA-STS mx pattern %q", pattern)
		}
		if normalizePolicyDomain(name) == "" {
			return fmt.Errorf("invalid MTA-STS mx pattern %q", pattern)
		}
	}
	if len(fields["max_age"]) != 1 {
		return fmt.Errorf("MTA-STS policy must contain exactly one max_age")
	}
	age, err := strconv.Atoi(fields["max_age"][0])
	if err != nil || age < 0 {
		return fmt.Errorf("MTA-STS max_age must be a non-negative integer")
	}
	out.MaxAge = age
	return nil
}

// AllowsMX reports whether a host matches one of the authenticated policy's
// exact or left-wildcard MX patterns.
func (p MTASTSPolicy) AllowsMX(host string) bool {
	host = normalizePolicyDomain(host)
	if p.Result != "valid" || host == "" {
		return false
	}
	for _, pattern := range p.MX {
		pattern = strings.ToLower(strings.TrimSuffix(pattern, "."))
		if host == pattern || (strings.HasPrefix(pattern, "*.") && strings.HasSuffix(host, pattern[1:]) && host != pattern[2:]) {
			return true
		}
	}
	return false
}

func parsePolicyTags(record string) map[string]string {
	out := map[string]string{}
	for _, part := range strings.Split(record, ";") {
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 {
			out[strings.ToLower(strings.TrimSpace(kv[0]))] = strings.TrimSpace(kv[1])
		}
	}
	return out
}

func normalizePolicyDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if len(domain) == 0 || len(domain) > 253 || strings.Contains(domain, "..") {
		return ""
	}
	for _, label := range strings.Split(domain, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return ""
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return ""
			}
		}
	}
	return domain
}

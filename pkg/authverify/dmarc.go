package authverify

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
	"golang.org/x/net/publicsuffix"
)

// DMARC result and policy values.
const (
	DMARCNone      = "none"
	DMARCPass      = "pass"
	DMARCFail      = "fail"
	DMARCTempError = "temperror"
	DMARCPermError = "permerror"

	PolicyNone       = "none"
	PolicyQuarantine = "quarantine"
	PolicyReject     = "reject"
)

// DMARCRecord is a parsed DMARC policy record (RFC 7489 section 6.3).
type DMARCRecord struct {
	Version string
	// Policy is the p= tag: what the domain owner asks receivers to do with
	// messages that fail.
	Policy string
	// SubdomainPolicy is the sp= tag, defaulting to Policy when absent.
	SubdomainPolicy string
	// ADKIM and ASPF are the alignment modes: "r" relaxed or "s" strict.
	ADKIM string
	ASPF  string
	// Percent is the pct= tag: the share of failing mail the policy applies
	// to. A domain ramping up deployment publishes p=reject with pct=10.
	Percent int
	// RUA and RUF are the aggregate and forensic reporting destinations.
	RUA []string
	RUF []string
	// Raw is the record as published.
	Raw string
	// Domain is the name the record was found at.
	Domain string
	// Organizational reports that the record came from the organisational
	// domain rather than the exact From domain, which selects sp= over p=.
	Organizational bool
}

// DMARCResult is the outcome of a DMARC evaluation.
type DMARCResult struct {
	Result string
	// Disposition is the action the policy calls for: none, quarantine, or
	// reject. It is "none" when the message passes.
	Disposition string
	// FromDomain is the RFC 5322 From domain the policy was looked up for.
	FromDomain string
	// Record is the policy that applied, if one was found.
	Record *DMARCRecord

	// SPFAligned and DKIMAligned report identifier alignment, which is the
	// part DMARC adds on top of the underlying mechanisms. An SPF pass for
	// an unrelated envelope domain does not satisfy DMARC.
	SPFAligned  bool
	DKIMAligned bool
	// AlignedDKIMDomains lists the passing d= values that aligned.
	AlignedDKIMDomains []string

	Explanation string
}

// LookupDMARC retrieves the DMARC record for a From domain, following the
// RFC 7489 section 6.6.3 discovery rule: try the exact domain, then fall back
// to the organisational domain.
func LookupDMARC(resolver *dnsx.Resolver, fromDomain string) (*DMARCRecord, error) {
	if !resolver.Enabled() {
		return nil, fmt.Errorf("no DNS resolver configured")
	}
	fromDomain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(fromDomain), "."))
	if fromDomain == "" {
		return nil, fmt.Errorf("empty From domain")
	}

	if record := fetchDMARCRecord(resolver, fromDomain); record != nil {
		record.Organizational = false
		return record, nil
	}

	org, err := publicsuffix.EffectiveTLDPlusOne(fromDomain)
	if err != nil || org == fromDomain {
		return nil, nil // no record published
	}

	if record := fetchDMARCRecord(resolver, org); record != nil {
		record.Organizational = true
		return record, nil
	}
	return nil, nil
}

func fetchDMARCRecord(resolver *dnsx.Resolver, domain string) *DMARCRecord {
	for _, txt := range resolver.LookupTXT("_dmarc." + domain) {
		trimmed := strings.TrimSpace(txt)
		if !strings.HasPrefix(strings.ToLower(trimmed), "v=dmarc1") {
			continue
		}
		record := parseDMARCRecord(trimmed)
		record.Domain = domain
		return record
	}
	return nil
}

// parseDMARCRecord parses the tag list of a DMARC record, applying the
// defaults RFC 7489 specifies for absent tags.
func parseDMARCRecord(raw string) *DMARCRecord {
	record := &DMARCRecord{
		Raw:     raw,
		ADKIM:   "r",
		ASPF:    "r",
		Percent: 100,
	}

	for _, part := range strings.Split(raw, ";") {
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		value := strings.TrimSpace(part[eq+1:])

		switch key {
		case "v":
			record.Version = value
		case "p":
			record.Policy = normalizePolicy(value)
		case "sp":
			record.SubdomainPolicy = normalizePolicy(value)
		case "adkim":
			if v := strings.ToLower(value); v == "s" || v == "r" {
				record.ADKIM = v
			}
		case "aspf":
			if v := strings.ToLower(value); v == "s" || v == "r" {
				record.ASPF = v
			}
		case "pct":
			if n, err := strconv.Atoi(value); err == nil && n >= 0 && n <= 100 {
				record.Percent = n
			}
		case "rua":
			record.RUA = splitURIList(value)
		case "ruf":
			record.RUF = splitURIList(value)
		}
	}

	if record.SubdomainPolicy == "" {
		record.SubdomainPolicy = record.Policy
	}
	return record
}

func normalizePolicy(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case PolicyReject:
		return PolicyReject
	case PolicyQuarantine:
		return PolicyQuarantine
	case PolicyNone:
		return PolicyNone
	}
	return ""
}

func splitURIList(v string) []string {
	var out []string
	for _, item := range strings.Split(v, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, item)
		}
	}
	return out
}

// VerifyDMARC evaluates DMARC given the results of the underlying mechanisms.
//
// It deliberately takes verified SPF and DKIM results rather than reading
// them from headers: the whole point is that the inputs must be ones this
// process computed, not ones the sender supplied.
func VerifyDMARC(resolver *dnsx.Resolver, fromDomain string, spf SPFResult, dkim DKIMResult) DMARCResult {
	result := DMARCResult{
		FromDomain:  strings.ToLower(strings.TrimSpace(fromDomain)),
		Disposition: PolicyNone,
	}

	if result.FromDomain == "" {
		result.Result = DMARCPermError
		result.Explanation = "message has no usable From domain"
		return result
	}

	record, err := LookupDMARC(resolver, result.FromDomain)
	if err != nil {
		result.Result = DMARCTempError
		result.Explanation = err.Error()
		return result
	}
	if record == nil {
		result.Result = DMARCNone
		result.Explanation = fmt.Sprintf("no DMARC record published for %q", result.FromDomain)
		return result
	}
	result.Record = record

	if record.Policy == "" {
		result.Result = DMARCPermError
		result.Explanation = "DMARC record has no valid p= tag"
		return result
	}

	// Identifier alignment (RFC 7489 section 3.1).
	strictSPF := record.ASPF == "s"
	if spf.Result == SPFPass && spf.Domain != "" {
		result.SPFAligned = domainsAlign(spf.Domain, result.FromDomain, strictSPF)
	}

	strictDKIM := record.ADKIM == "s"
	for _, d := range dkim.PassingDomains {
		if domainsAlign(d, result.FromDomain, strictDKIM) {
			result.DKIMAligned = true
			result.AlignedDKIMDomains = append(result.AlignedDKIMDomains, d)
		}
	}

	if result.SPFAligned || result.DKIMAligned {
		result.Result = DMARCPass
		result.Explanation = alignmentSummary(result)
		return result
	}

	result.Result = DMARCFail

	// The applicable policy is sp= when the record was inherited from the
	// organisational domain, p= otherwise.
	policy := record.Policy
	if record.Organizational && record.SubdomainPolicy != "" {
		policy = record.SubdomainPolicy
	}
	result.Disposition = policy

	// pct< 100 means the domain owner asked receivers to apply the policy to
	// only a sample. Applying it to everything would over-block during a
	// staged rollout, so the disposition is softened rather than the result.
	if record.Percent < 100 && policy == PolicyReject {
		result.Disposition = PolicyQuarantine
		result.Explanation = fmt.Sprintf(
			"DMARC failed; policy is reject at pct=%d, so the sampled disposition is quarantine", record.Percent)
		return result
	}

	result.Explanation = fmt.Sprintf(
		"DMARC failed: SPF %s (%s, aligned=%t), DKIM %s (aligned=%t); policy %s",
		spf.Result, spf.Domain, result.SPFAligned, dkim.Result, result.DKIMAligned, policy)
	return result
}

func alignmentSummary(r DMARCResult) string {
	switch {
	case r.SPFAligned && r.DKIMAligned:
		return "DMARC passed: both SPF and DKIM align with the From domain"
	case r.DKIMAligned:
		return fmt.Sprintf("DMARC passed: DKIM aligns (%s)", strings.Join(r.AlignedDKIMDomains, ", "))
	default:
		return "DMARC passed: SPF aligns with the From domain"
	}
}

// domainsAlign implements DMARC identifier alignment. Relaxed alignment
// compares organisational domains; strict requires an exact match.
func domainsAlign(a, b string, strict bool) bool {
	a = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a), "."))
	b = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(b), "."))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if strict {
		return false
	}

	orgA, errA := publicsuffix.EffectiveTLDPlusOne(a)
	orgB, errB := publicsuffix.EffectiveTLDPlusOne(b)
	if errA != nil || errB != nil {
		return false
	}
	return orgA == orgB
}

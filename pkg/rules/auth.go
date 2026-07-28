package rules

import (
	"strings"
)

// AuthResults is the consolidated view of a message's authentication state as
// *reported* by upstream, assembled from Authentication-Results, Received-SPF,
// ARC-Authentication-Results and the raw DKIM-Signature fields.
//
// These values are not trustworthy on their own. Anyone can put
//
//	Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
//
// in a message they send, and a filter that believes it is trivially
// bypassed. Two things make the data usable:
//
//   - Trusted reports whether the header was written by an authserv-id the
//     operator configured as their own. Only a trusted header means anything.
//   - MessageContext.Verified holds results this process computed from the
//     message bytes and DNS. Prefer it whenever it is present.
//
// Rules that need a real answer should call the verified builtins
// (verify_spf, verify_dkim, verify_dmarc, is_verified) rather than these.
//
// Every result string uses the RFC 8601 vocabulary: "pass", "fail",
// "softfail", "neutral", "none", "temperror", "permerror", or "" when the
// method was not reported at all. "none" and "" are meaningfully different:
// the former means the authserv evaluated and found no policy, the latter
// means nobody evaluated it.
type AuthResults struct {
	// AuthServID is the identity of the ADMD that performed the checks.
	AuthServID string

	SPF   string
	DKIM  string
	DMARC string
	ARC   string

	// SPFDomain is the identity SPF authenticated (smtp.mailfrom or helo).
	SPFDomain string
	// DKIMDomains lists every d= domain with a passing signature.
	DKIMDomains []string
	// DKIMAllDomains lists every d= domain seen, passing or not.
	DKIMAllDomains []string
	// DMARCPolicy is the p= value when the verifier reported one.
	DMARCPolicy string

	// Present reports whether any Authentication-Results header was found.
	// Without one, absence of a pass is not evidence of failure.
	Present bool

	// Trusted reports whether at least one Authentication-Results header
	// carried an authserv-id listed in MessageContext.TrustedAuthServs.
	// When no trust list is configured this stays false, because a header
	// whose author is unknown proves nothing.
	Trusted bool

	// UntrustedAuthServs lists the authserv-ids that were seen but not
	// trusted, which is what to log when a message arrives carrying a forged
	// pass from someone else's hostname.
	UntrustedAuthServs []string

	// Signed reports whether the message carries any DKIM-Signature field,
	// independent of whether a verifier checked it.
	Signed bool
}

// AuthResults parses and caches the message's authentication state.
func (m *MessageContext) AuthResults() *AuthResults {
	if m.authParsed {
		return m.auth
	}
	m.auth = parseAuthResults(m)
	m.authParsed = true
	return m.auth
}

func parseAuthResults(m *MessageContext) *AuthResults {
	ar := &AuthResults{}

	for _, sig := range m.GetAll("DKIM-Signature") {
		ar.Signed = true
		if d := extractTag(sig, "d"); d != "" {
			ar.DKIMAllDomains = appendUnique(ar.DKIMAllDomains, strings.ToLower(d))
		}
	}

	headers := m.GetAll("Authentication-Results")
	headers = append(headers, m.GetAll("ARC-Authentication-Results")...)
	headers = append(headers, m.GetAll("X-Authentication-Results")...)

	trusted := make(map[string]bool, len(m.TrustedAuthServs))
	for _, id := range m.TrustedAuthServs {
		trusted[strings.ToLower(strings.TrimSpace(id))] = true
	}

	for _, h := range headers {
		if strings.TrimSpace(h) == "" {
			continue
		}
		ar.Present = true

		// Determine the authserv-id before parsing the clauses, so a header
		// from an unknown authority can be recorded without its claims being
		// mistaken for a verdict this system stands behind.
		id := strings.ToLower(authServIDOf(h))
		if len(trusted) > 0 {
			if trusted[id] {
				ar.Trusted = true
			} else {
				ar.UntrustedAuthServs = appendUnique(ar.UntrustedAuthServs, id)
			}
		}

		parseAuthResultHeader(h, ar)
	}

	// Received-SPF is the older, single-method form. Only consult it when
	// Authentication-Results did not already report SPF.
	if ar.SPF == "" {
		for _, h := range m.GetAll("Received-SPF") {
			result, domain := parseReceivedSPF(h)
			if result != "" {
				ar.SPF = result
				if ar.SPFDomain == "" {
					ar.SPFDomain = domain
				}
				break
			}
		}
	}

	return ar
}

// parseAuthResultHeader parses one Authentication-Results field. The grammar
// is authserv-id followed by semicolon-separated "method=result" clauses,
// each optionally carrying "ptype.property=value" pairs.
func parseAuthResultHeader(header string, ar *AuthResults) {
	clauses := splitOutsideQuotes(header, ';')
	for i, clause := range clauses {
		clause = strings.TrimSpace(clause)
		if clause == "" {
			continue
		}

		if i == 0 && !strings.Contains(clause, "=") {
			if ar.AuthServID == "" {
				ar.AuthServID = strings.Fields(clause)[0]
			}
			continue
		}

		fields := strings.Fields(clause)
		if len(fields) == 0 {
			continue
		}

		method, result := splitKV(fields[0])
		method = strings.ToLower(method)
		result = strings.ToLower(strings.Trim(result, "\""))

		// Some verifiers emit a comment before the result, e.g.
		// spf=pass (google.com: domain of x designates ...).
		if result == "" {
			continue
		}

		props := map[string]string{}
		for _, f := range fields[1:] {
			k, v := splitKV(f)
			if k == "" || v == "" {
				continue
			}
			props[strings.ToLower(k)] = strings.Trim(v, "\"")
		}

		switch method {
		case "spf":
			// Keep the strongest result seen; a pass from any authserv beats
			// an absent one, but never let a later "none" erase a "fail".
			ar.SPF = strongerResult(ar.SPF, result)
			if d := firstNonEmpty(props["smtp.mailfrom"], props["smtp.helo"]); d != "" {
				ar.SPFDomain = strings.ToLower(domainPart(d))
			}
		case "dkim":
			ar.DKIM = strongerResult(ar.DKIM, result)
			if d := props["header.d"]; d != "" {
				d = strings.ToLower(d)
				ar.DKIMAllDomains = appendUnique(ar.DKIMAllDomains, d)
				if result == "pass" {
					ar.DKIMDomains = appendUnique(ar.DKIMDomains, d)
				}
			}
		case "dmarc":
			ar.DMARC = strongerResult(ar.DMARC, result)
			if p := firstNonEmpty(props["policy.dmarc"], props["p"]); p != "" {
				ar.DMARCPolicy = strings.ToLower(p)
			}
		case "arc":
			ar.ARC = strongerResult(ar.ARC, result)
		}
	}
}

// strongerResult decides which of two reported results to keep. A definitive
// verdict (pass or fail) outranks an inconclusive one, and an existing
// definitive verdict is never downgraded.
func strongerResult(existing, incoming string) string {
	if existing == "" {
		return incoming
	}
	rank := func(s string) int {
		switch s {
		case "fail":
			return 4
		case "pass":
			return 3
		case "softfail", "permerror", "temperror":
			return 2
		case "neutral", "none":
			return 1
		default:
			return 0
		}
	}
	if rank(incoming) > rank(existing) {
		return incoming
	}
	return existing
}

// parseReceivedSPF extracts the result and identity from a Received-SPF field.
func parseReceivedSPF(header string) (result, domain string) {
	trimmed := strings.TrimSpace(header)
	if trimmed == "" {
		return "", ""
	}
	fields := strings.Fields(trimmed)
	if len(fields) == 0 {
		return "", ""
	}
	result = strings.ToLower(strings.Trim(fields[0], ";"))
	switch result {
	case "pass", "fail", "softfail", "neutral", "none", "temperror", "permerror":
	default:
		return "", ""
	}

	for _, f := range fields[1:] {
		k, v := splitKV(strings.Trim(f, ";"))
		if strings.EqualFold(k, "envelope-from") || strings.EqualFold(k, "smtp.mailfrom") {
			domain = strings.ToLower(domainPart(strings.Trim(v, "<>\"")))
		}
	}
	return result, domain
}

// SPFAligned reports whether the SPF-authenticated domain aligns with the
// header From domain, using DMARC relaxed alignment (organisational domain
// match) unless strict is requested.
func (m *MessageContext) SPFAligned(strict bool) bool {
	ar := m.AuthResults()
	if ar.SPF != "pass" || ar.SPFDomain == "" {
		return false
	}
	return domainsAlign(ar.SPFDomain, DomainOf(m.Get("From")), strict)
}

// DKIMAligned reports whether any passing DKIM signature's d= domain aligns
// with the header From domain.
func (m *MessageContext) DKIMAligned(strict bool) bool {
	ar := m.AuthResults()
	if ar.DKIM != "pass" {
		return false
	}
	from := DomainOf(m.Get("From"))
	for _, d := range ar.DKIMDomains {
		if domainsAlign(d, from, strict) {
			return true
		}
	}
	return false
}

// DMARCPass reports whether the message satisfies DMARC: a reported DMARC
// pass, or an aligned SPF or DKIM pass when no verifier reported DMARC.
func (m *MessageContext) DMARCPass() bool {
	ar := m.AuthResults()
	if ar.DMARC == "pass" {
		return true
	}
	if ar.DMARC == "fail" {
		return false
	}
	return m.SPFAligned(false) || m.DKIMAligned(false)
}

// domainsAlign implements DMARC identifier alignment. Strict alignment
// requires an exact match; relaxed alignment requires the organisational
// domains to match.
func domainsAlign(a, b string, strict bool) bool {
	a = strings.ToLower(strings.TrimSuffix(a, "."))
	b = strings.ToLower(strings.TrimSuffix(b, "."))
	if a == "" || b == "" {
		return false
	}
	if a == b {
		return true
	}
	if strict {
		return false
	}
	return RegisteredDomain(a) == RegisteredDomain(b)
}

// authServIDOf extracts the authserv-id, which is the first token of an
// Authentication-Results field.
func authServIDOf(header string) string {
	clean := strings.TrimSpace(stripComments(header))
	if clean == "" {
		return ""
	}
	// The id ends at the first semicolon or whitespace.
	if i := strings.IndexAny(clean, "; \t"); i > 0 {
		clean = clean[:i]
	}
	return strings.TrimSuffix(strings.TrimSpace(clean), ".")
}

func extractTag(sig, tag string) string {
	for _, part := range strings.Split(sig, ";") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(part, tag+"=") {
			return strings.TrimSpace(part[len(tag)+1:])
		}
	}
	return ""
}

func splitKV(s string) (string, string) {
	i := strings.Index(s, "=")
	if i < 0 {
		return s, ""
	}
	return strings.TrimSpace(s[:i]), strings.TrimSpace(s[i+1:])
}

func domainPart(s string) string {
	if i := strings.LastIndex(s, "@"); i >= 0 {
		return s[i+1:]
	}
	return s
}

// stripComments removes RFC 5322 parenthesised comments, which routinely
// contain semicolons and equals signs that would otherwise be mistaken for
// clause separators and property assignments. Parentheses inside a quoted
// string are literal and are preserved.
func stripComments(s string) string {
	var out strings.Builder
	inQuote := false
	depth := 0
	for _, r := range s {
		switch {
		case r == '"' && depth == 0:
			inQuote = !inQuote
			out.WriteRune(r)
		case r == '(' && !inQuote:
			depth++
		case r == ')' && !inQuote:
			if depth > 0 {
				depth--
				out.WriteRune(' ') // a comment is folding whitespace
			} else {
				out.WriteRune(r)
			}
		default:
			if depth == 0 {
				out.WriteRune(r)
			}
		}
	}
	return out.String()
}

// splitOutsideQuotes splits on a separator that appears outside quoted
// strings, after comments have been removed.
func splitOutsideQuotes(s string, sep rune) []string {
	s = stripComments(s)

	var out []string
	var cur strings.Builder
	inQuote := false
	for _, r := range s {
		if r == '"' {
			inQuote = !inQuote
		}
		if r == sep && !inQuote {
			out = append(out, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteRune(r)
	}
	out = append(out, cur.String())
	return out
}

func appendUnique(list []string, v string) []string {
	for _, existing := range list {
		if existing == v {
			return list
		}
	}
	return append(list, v)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

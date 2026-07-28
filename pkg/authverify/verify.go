package authverify

import (
	"fmt"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

// Input is everything the verifiers need about one message.
type Input struct {
	// Headers are the message's fields in received order, with values
	// exactly as they appeared on the wire. DKIM canonicalisation operates
	// on these bytes, so any normalisation upstream will break verification.
	Headers [][2]string
	// Body is the raw body after the blank separator line.
	Body []byte

	// ClientIP is the address that connected to the MTA. SPF is meaningless
	// without it.
	ClientIP string
	// MailFrom is the SMTP envelope sender (RFC 5321 MAIL FROM).
	MailFrom string
	// HELO is the name the client announced.
	HELO string
	// FromDomain overrides the RFC 5322 From domain used for DMARC. When
	// empty it is derived from the From header.
	FromDomain string

	// Now is the reference time for signature expiry. Zero means time.Now().
	Now time.Time

	// CheckDANE enables TLSA lookups for the sender domain's MX hosts. It is
	// off by default because it costs a DNS round trip per MX host and says
	// nothing about the message itself.
	CheckDANE bool
}

// Result is the consolidated verification outcome.
type Result struct {
	SPF   SPFResult
	DKIM  DKIMResult
	DMARC DMARCResult
	DANE  *DANEDomainResult

	// FromDomain is the identity DMARC was evaluated for.
	FromDomain string

	// Authenticated reports whether the message proved control of the From
	// domain: a DMARC pass, which requires an aligned SPF or DKIM pass.
	Authenticated bool

	// Elapsed is how long verification took, including DNS.
	Elapsed time.Duration
}

// Verify runs SPF, DKIM, DMARC and optionally DANE against a message.
//
// The verifiers are run in the order SPF, DKIM, DMARC because DMARC consumes
// the results of the first two. Nothing here reads Authentication-Results:
// every verdict is derived from the message bytes and DNS, so a forged
// Authentication-Results header cannot influence the outcome.
func Verify(resolver *dnsx.Resolver, input Input) *Result {
	start := time.Now()

	now := input.Now
	if now.IsZero() {
		now = time.Now()
	}

	result := &Result{}

	fromDomain := strings.ToLower(strings.TrimSpace(input.FromDomain))
	if fromDomain == "" {
		fromDomain = domainOfAddress(headerValue(input.Headers, "From"))
	}
	result.FromDomain = fromDomain

	// SPF needs the connecting address; without one the mechanism cannot be
	// evaluated and reporting a pass would be a lie.
	if input.ClientIP != "" {
		result.SPF = VerifySPF(resolver, input.ClientIP, input.MailFrom, input.HELO)
	} else {
		result.SPF = SPFResult{
			Result:      SPFNone,
			Domain:      domainOfAddress(input.MailFrom),
			Explanation: "no client IP supplied; SPF cannot be evaluated",
		}
	}

	result.DKIM = VerifyDKIM(resolver, input.Headers, input.Body, now)

	result.DMARC = VerifyDMARC(resolver, fromDomain, result.SPF, result.DKIM)
	result.Authenticated = result.DMARC.Result == DMARCPass

	if input.CheckDANE && fromDomain != "" {
		dane := CheckDANEDomain(resolver, fromDomain)
		result.DANE = &dane
	}

	result.Elapsed = time.Since(start)
	return result
}

// AuthenticationResults renders the verdict as an RFC 8601
// Authentication-Results field, which is how the result is handed to
// downstream systems.
//
// The authserv-id must be this host's own identity. Downstream consumers can
// only trust the field if they know which authserv-id belongs to their own
// infrastructure and discard fields bearing any other.
func (r *Result) AuthenticationResults(authservID string) string {
	if authservID == "" {
		authservID = "mailscript"
	}

	parts := []string{authservID}

	spf := fmt.Sprintf("spf=%s", r.SPF.Result)
	if r.SPF.Domain != "" {
		spf += fmt.Sprintf(" smtp.mailfrom=%s", r.SPF.Domain)
	}
	parts = append(parts, spf)

	dkim := fmt.Sprintf("dkim=%s", r.DKIM.Result)
	if len(r.DKIM.PassingDomains) > 0 {
		dkim += fmt.Sprintf(" header.d=%s", r.DKIM.PassingDomains[0])
	}
	parts = append(parts, dkim)

	dmarc := fmt.Sprintf("dmarc=%s", r.DMARC.Result)
	if r.DMARC.Record != nil && r.DMARC.Record.Policy != "" {
		dmarc += fmt.Sprintf(" policy.dmarc=%s", r.DMARC.Record.Policy)
	}
	if r.FromDomain != "" {
		dmarc += fmt.Sprintf(" header.from=%s", r.FromDomain)
	}
	parts = append(parts, dmarc)

	if r.DANE != nil {
		parts = append(parts, fmt.Sprintf("dane=%s", r.DANE.Result))
	}

	return strings.Join(parts, "; ")
}

// Summary returns a one-line human-readable verdict.
func (r *Result) Summary() string {
	verdict := "not authenticated"
	if r.Authenticated {
		verdict = "authenticated"
	}
	base := fmt.Sprintf("%s (spf=%s dkim=%s dmarc=%s",
		verdict, r.SPF.Result, r.DKIM.Result, r.DMARC.Result)
	if r.DANE != nil {
		base += " dane=" + r.DANE.Result
	}
	return base + ")"
}

// Disposition returns the action DMARC policy calls for: "none",
// "quarantine", or "reject".
func (r *Result) Disposition() string {
	if r.Authenticated {
		return PolicyNone
	}
	if r.DMARC.Disposition == "" {
		return PolicyNone
	}
	return r.DMARC.Disposition
}

// Warnings lists conditions that a passing result should not hide, such as a
// DKIM signature that covers only part of the body.
func (r *Result) Warnings() []string {
	var out []string

	for _, sig := range r.DKIM.Signatures {
		if sig.BodyTruncated {
			out = append(out, fmt.Sprintf(
				"DKIM signature from %s covers only %d of %d body bytes; the remainder is unsigned and can be replaced",
				sig.Domain, sig.SignedBytes, sig.BodyBytes))
		}
		if sig.TimestampFuture {
			out = append(out, fmt.Sprintf("DKIM signature from %s is timestamped in the future", sig.Domain))
		}
		if sig.Result == DKIMPolicy {
			out = append(out, fmt.Sprintf("DKIM signature from %s rejected on policy: %s", sig.Domain, sig.Explanation))
		}
		if sig.Result == DKIMPass && sig.KeyBits > 0 && sig.KeyBits < 2048 && sig.KeyBits != 256 {
			out = append(out, fmt.Sprintf(
				"DKIM signature from %s uses a %d-bit key; RFC 8301 recommends at least 2048",
				sig.Domain, sig.KeyBits))
		}
	}

	if r.SPF.Result == SPFPermError {
		out = append(out, "SPF evaluation hit a permanent error: "+r.SPF.Explanation)
	}
	if r.DMARC.Record != nil && r.DMARC.Record.Policy == PolicyNone {
		out = append(out, fmt.Sprintf(
			"%s publishes DMARC p=none, so a failure carries no enforcement request", r.DMARC.Record.Domain))
	}
	if r.DANE != nil && r.DANE.Result == DANEInsecure {
		out = append(out, "DANE: "+r.DANE.Explanation)
	}

	return out
}

// headerValue returns the first value of a named header.
func headerValue(headers [][2]string, name string) string {
	for _, h := range headers {
		if strings.EqualFold(strings.TrimSpace(h[0]), name) {
			return h[1]
		}
	}
	return ""
}

// domainOfAddress extracts the domain from an address field without pulling
// in the full parser, which lives in the rules package.
func domainOfAddress(field string) string {
	field = strings.TrimSpace(field)
	if field == "" {
		return ""
	}

	// Prefer the angle-addr when present, since a display name may itself
	// contain an at-sign placed there to confuse naive parsers.
	if open := strings.LastIndex(field, "<"); open >= 0 {
		if end := strings.Index(field[open:], ">"); end > 0 {
			field = field[open+1 : open+end]
		}
	}

	at := strings.LastIndex(field, "@")
	if at < 0 {
		return ""
	}
	domain := field[at+1:]
	domain = strings.Trim(strings.TrimSpace(domain), "<>\"' \t;,")
	return strings.ToLower(strings.TrimSuffix(domain, "."))
}

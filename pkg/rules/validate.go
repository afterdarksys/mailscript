package rules

import (
	"fmt"
	"net/mail"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Severity levels reported by header validation, ordered by how strongly they
// should influence a policy decision.
const (
	SeverityInfo     = "info"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Finding is a single header validation result.
type Finding struct {
	Code     string  // stable machine-readable identifier
	Severity string  // one of the Severity constants
	Header   string  // the header the finding relates to, if any
	Message  string  // human-readable explanation
	Score    float64 // suggested score contribution
}

// severityRank orders severities for filtering and sorting.
func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	}
	return 0
}

// singletonHeaders may appear at most once per RFC 5322 section 3.6. A second
// occurrence is either a broken sender or a deliberate attempt to make the
// MUA and the filter disagree about which value is real.
var singletonHeaders = []string{
	"Date", "From", "Sender", "Reply-To", "To", "Cc", "Bcc",
	"Message-ID", "In-Reply-To", "References", "Subject",
	"MIME-Version", "Content-Type", "Content-Transfer-Encoding",
}

// Limits used by structural checks. They are generous: the goal is to catch
// abuse and corruption, not to enforce style.
const (
	maxHeaderLineOctets = 998   // RFC 5322 section 2.1.1
	maxHeaderCount      = 200   // beyond this, something is wrong
	maxHeaderBlockSize  = 65536 // 64 KiB of headers
	maxSubjectRunes     = 500
	maxReceivedHops     = 30
	futureSkewTolerance = 24 * time.Hour
	staleDateTolerance  = 365 * 24 * time.Hour
)

// ValidateHeaders runs the full header validation suite and returns every
// finding, ordered most severe first.
func (m *MessageContext) ValidateHeaders() []Finding {
	var findings []Finding
	add := func(f Finding) { findings = append(findings, f) }

	m.checkStructure(add)
	m.checkRequiredFields(add)
	m.checkDuplicates(add)
	m.checkAddresses(add)
	m.checkSpoofing(add)
	m.checkDate(add)
	m.checkMessageID(add)
	m.checkMIME(add)
	m.checkReceivedChain(add)
	m.checkAuthentication(add)

	// Stable sort by descending severity, preserving discovery order within a
	// severity so output is deterministic.
	for i := 1; i < len(findings); i++ {
		for j := i; j > 0 && severityRank(findings[j].Severity) > severityRank(findings[j-1].Severity); j-- {
			findings[j], findings[j-1] = findings[j-1], findings[j]
		}
	}
	return findings
}

// checkStructure validates the physical form of the header block: field name
// syntax, embedded control characters, line lengths, and overall size.
func (m *MessageContext) checkStructure(add func(Finding)) {
	if len(m.HeaderList) > maxHeaderCount {
		add(Finding{
			Code: "HDR_COUNT_EXCESSIVE", Severity: SeverityLow,
			Message: fmt.Sprintf("message carries %d header fields (limit %d)", len(m.HeaderList), maxHeaderCount),
			Score:   1.0,
		})
	}
	if m.HeaderSize > maxHeaderBlockSize {
		add(Finding{
			Code: "HDR_SIZE_EXCESSIVE", Severity: SeverityLow,
			Message: fmt.Sprintf("header block is %d bytes (limit %d)", m.HeaderSize, maxHeaderBlockSize),
			Score:   1.0,
		})
	}

	for _, h := range m.HeaderList {
		if h.Name == "" {
			add(Finding{
				Code: "HDR_NO_COLON", Severity: SeverityHigh,
				Message: fmt.Sprintf("header block line %d has no field name: %q", h.LineNum, truncateStr(h.Raw, 60)),
				Score:   3.0,
			})
			continue
		}

		if !isValidFieldName(h.Name) {
			add(Finding{
				Code: "HDR_NAME_INVALID", Severity: SeverityHigh, Header: h.Name,
				Message: fmt.Sprintf("field name %q contains characters outside RFC 5322 ftext", truncateStr(h.Name, 40)),
				Score:   3.0,
			})
		}

		// A bare CR, LF or NUL surviving into a parsed value means the field
		// was assembled from attacker-controlled input without sanitising.
		if strings.ContainsAny(h.Value, "\r\n\x00") {
			add(Finding{
				Code: "HDR_INJECTION", Severity: SeverityCritical, Header: h.Name,
				Message: fmt.Sprintf("field %q contains an embedded control character (header injection)", h.Name),
				Score:   8.0,
			})
		}

		if h.MaxOctet > maxHeaderLineOctets {
			add(Finding{
				Code: "HDR_LINE_TOO_LONG", Severity: SeverityLow, Header: h.Name,
				Message: fmt.Sprintf("field %q has a %d-octet line (RFC 5322 limit is %d)", h.Name, h.MaxOctet, maxHeaderLineOctets),
				Score:   0.5,
			})
		}

		if hasRawNonASCII(h.Value) {
			add(Finding{
				Code: "HDR_8BIT_UNENCODED", Severity: SeverityMedium, Header: h.Name,
				Message: fmt.Sprintf("field %q contains raw 8-bit octets; RFC 2047 encoding is required without SMTPUTF8", h.Name),
				Score:   1.5,
			})
		}

		if !utf8.ValidString(h.Value) {
			add(Finding{
				Code: "HDR_INVALID_UTF8", Severity: SeverityMedium, Header: h.Name,
				Message: fmt.Sprintf("field %q is not valid UTF-8", h.Name),
				Score:   1.5,
			})
		}

		if strings.Contains(h.Value, "=?") && !isDecodableEncodedWord(h.Value) {
			add(Finding{
				Code: "HDR_2047_MALFORMED", Severity: SeverityLow, Header: h.Name,
				Message: fmt.Sprintf("field %q has a malformed RFC 2047 encoded-word", h.Name),
				Score:   1.0,
			})
		}
	}
}

// checkRequiredFields verifies the fields RFC 5322 section 3.6 requires.
func (m *MessageContext) checkRequiredFields(add func(Finding)) {
	if !m.Has("From") {
		add(Finding{
			Code: "HDR_FROM_MISSING", Severity: SeverityHigh, Header: "From",
			Message: "message has no From field, which RFC 5322 requires",
			Score:   5.0,
		})
	}
	if !m.Has("Date") {
		add(Finding{
			Code: "HDR_DATE_MISSING", Severity: SeverityMedium, Header: "Date",
			Message: "message has no Date field, which RFC 5322 requires",
			Score:   2.0,
		})
	}
	if !m.Has("Message-ID") {
		add(Finding{
			Code: "HDR_MSGID_MISSING", Severity: SeverityLow, Header: "Message-ID",
			Message: "message has no Message-ID field",
			Score:   1.5,
		})
	}

	subject := m.Get("Subject")
	if strings.IndexFunc(subject, func(r rune) bool {
		return r < 0x20 && r != '\t'
	}) >= 0 {
		add(Finding{
			Code: "HDR_SUBJECT_CONTROL", Severity: SeverityMedium, Header: "Subject",
			Message: "Subject contains control characters",
			Score:   2.0,
		})
	}
	if utf8.RuneCountInString(subject) > maxSubjectRunes {
		add(Finding{
			Code: "HDR_SUBJECT_TOO_LONG", Severity: SeverityLow, Header: "Subject",
			Message: fmt.Sprintf("Subject is %d characters", utf8.RuneCountInString(subject)),
			Score:   1.0,
		})
	}
}

// checkDuplicates flags repeated occurrences of fields that RFC 5322 permits
// only once.
func (m *MessageContext) checkDuplicates(add func(Finding)) {
	for _, name := range singletonHeaders {
		count := m.Count(name)
		if count <= 1 {
			continue
		}

		severity, score := SeverityMedium, 3.0
		// A duplicated From or Sender lets the MUA and the filter read
		// different identities, which is the whole point of the attack.
		if name == "From" || name == "Sender" || name == "Reply-To" {
			severity, score = SeverityHigh, 6.0
		}

		add(Finding{
			Code:     "HDR_DUP_" + strings.ToUpper(strings.ReplaceAll(name, "-", "_")),
			Severity: severity, Header: name,
			Message: fmt.Sprintf("field %q appears %d times but RFC 5322 allows at most one", name, count),
			Score:   score,
		})
	}
}

// checkAddresses validates the syntax of every address-bearing field.
func (m *MessageContext) checkAddresses(add func(Finding)) {
	for _, name := range []string{"From", "Sender", "Reply-To", "To", "Cc", "Bcc"} {
		raw := m.Get(name)
		if strings.TrimSpace(raw) == "" {
			continue
		}
		if _, err := mail.ParseAddressList(raw); err != nil {
			add(Finding{
				Code: "HDR_ADDR_INVALID", Severity: SeverityMedium, Header: name,
				Message: fmt.Sprintf("field %q is not a valid address list: %v", name, err),
				Score:   2.5,
			})
		}
	}

	for _, addr := range ParseAddressList(m.Get("From")) {
		if addr.Domain == "" {
			add(Finding{
				Code: "HDR_FROM_NO_DOMAIN", Severity: SeverityHigh, Header: "From",
				Message: fmt.Sprintf("From address %q has no domain part", truncateStr(addr.Address, 60)),
				Score:   4.0,
			})
		}
	}
}

// checkSpoofing looks for the identity mismatches that characterise
// impersonation: a display name that claims a different address, a From that
// disagrees with the envelope, and homoglyph domains.
func (m *MessageContext) checkSpoofing(add func(Finding)) {
	fromList := ParseAddressList(m.Get("From"))
	if len(fromList) == 0 {
		return
	}
	from := fromList[0]

	// A display name containing an email address that is not the real one is
	// the classic "Support <billing@evil.com>" pattern rendered as
	// "support@bank.com <billing@evil.com>".
	if claimed := extractAddressFromText(from.Name); claimed != "" {
		if !strings.EqualFold(claimed, from.Address) {
			severity := SeverityMedium
			score := 4.0
			if !SameOrgDomain(DomainOf(claimed), from.Domain) {
				severity = SeverityHigh
				score = 7.0
			}
			add(Finding{
				Code: "SPOOF_DISPLAY_NAME_ADDR", Severity: severity, Header: "From",
				Message: fmt.Sprintf("From display name claims %q but the actual address is %q", claimed, from.Address),
				Score:   score,
			})
		}
	}

	if IsMixedScript(from.Name) {
		add(Finding{
			Code: "SPOOF_DISPLAY_NAME_MIXED_SCRIPT", Severity: SeverityMedium, Header: "From",
			Message: fmt.Sprintf("From display name mixes Unicode scripts: %s", strings.Join(ScriptsIn(from.Name), ", ")),
			Score:   3.0,
		})
	}

	unicodeDomain := ToUnicodeDomain(from.Domain)
	if IsMixedScript(unicodeDomain) {
		add(Finding{
			Code: "SPOOF_DOMAIN_MIXED_SCRIPT", Severity: SeverityHigh, Header: "From",
			Message: fmt.Sprintf("From domain %q mixes Unicode scripts", unicodeDomain),
			Score:   6.0,
		})
	}

	// Reply-To pointing somewhere unrelated to From is how a reply gets
	// redirected to the attacker after the recipient trusts the sender.
	if replyTo := m.Get("Reply-To"); replyTo != "" {
		rt := ParseAddress(replyTo)
		if rt.Domain != "" && from.Domain != "" && !SameOrgDomain(rt.Domain, from.Domain) {
			add(Finding{
				Code: "SPOOF_REPLYTO_MISMATCH", Severity: SeverityMedium, Header: "Reply-To",
				Message: fmt.Sprintf("Reply-To domain %q differs from From domain %q", rt.Domain, from.Domain),
				Score:   2.5,
			})
		}
	}

	// The envelope sender is what SPF authenticates; a mismatch with the
	// header From is normal for forwarders and lists but notable otherwise.
	envelope := m.envelopeSender()
	if envelope != "" && from.Domain != "" {
		envDomain := DomainOf(envelope)
		if envDomain != "" && !SameOrgDomain(envDomain, from.Domain) && !m.isListMail() {
			add(Finding{
				Code: "SPOOF_ENVELOPE_MISMATCH", Severity: SeverityLow, Header: "From",
				Message: fmt.Sprintf("envelope sender domain %q differs from From domain %q", envDomain, from.Domain),
				Score:   1.5,
			})
		}
	}

	if sender := m.Get("Sender"); sender != "" {
		sd := DomainOf(sender)
		if sd != "" && from.Domain != "" && !SameOrgDomain(sd, from.Domain) {
			add(Finding{
				Code: "SPOOF_SENDER_MISMATCH", Severity: SeverityLow, Header: "Sender",
				Message: fmt.Sprintf("Sender domain %q differs from From domain %q", sd, from.Domain),
				Score:   1.0,
			})
		}
	}

	if len(fromList) > 1 {
		add(Finding{
			Code: "SPOOF_MULTIPLE_FROM_ADDRS", Severity: SeverityMedium, Header: "From",
			Message: fmt.Sprintf("From lists %d addresses without a Sender field", len(fromList)),
			Score:   3.0,
		})
	}
}

// checkDate validates the Date field and its skew from the reference time.
func (m *MessageContext) checkDate(add func(Finding)) {
	raw := m.Get("Date")
	if raw == "" {
		return
	}

	parsed, err := mail.ParseDate(raw)
	if err != nil {
		add(Finding{
			Code: "HDR_DATE_UNPARSEABLE", Severity: SeverityMedium, Header: "Date",
			Message: fmt.Sprintf("Date %q is not a valid RFC 5322 date: %v", truncateStr(raw, 60), err),
			Score:   2.0,
		})
		return
	}

	now := m.RefTime()
	if parsed.After(now.Add(futureSkewTolerance)) {
		add(Finding{
			Code: "HDR_DATE_FUTURE", Severity: SeverityMedium, Header: "Date",
			Message: fmt.Sprintf("Date is %s in the future", parsed.Sub(now).Round(time.Hour)),
			Score:   3.0,
		})
	}
	if parsed.Before(now.Add(-staleDateTolerance)) {
		add(Finding{
			Code: "HDR_DATE_STALE", Severity: SeverityLow, Header: "Date",
			Message: fmt.Sprintf("Date is %s in the past", now.Sub(parsed).Round(24*time.Hour)),
			Score:   1.0,
		})
	}
}

// checkMessageID validates Message-ID syntax and its relationship to From.
func (m *MessageContext) checkMessageID(add func(Finding)) {
	raw := strings.TrimSpace(m.Get("Message-ID"))
	if raw == "" {
		return
	}

	if !strings.HasPrefix(raw, "<") || !strings.HasSuffix(raw, ">") || len(raw) < 4 {
		add(Finding{
			Code: "HDR_MSGID_MALFORMED", Severity: SeverityLow, Header: "Message-ID",
			Message: fmt.Sprintf("Message-ID %q is not enclosed in angle brackets", truncateStr(raw, 60)),
			Score:   1.5,
		})
		return
	}

	inner := raw[1 : len(raw)-1]
	at := strings.LastIndex(inner, "@")
	if at <= 0 || at == len(inner)-1 {
		add(Finding{
			Code: "HDR_MSGID_MALFORMED", Severity: SeverityLow, Header: "Message-ID",
			Message: fmt.Sprintf("Message-ID %q has no id-right domain part", truncateStr(raw, 60)),
			Score:   1.5,
		})
		return
	}

	idDomain := strings.ToLower(inner[at+1:])
	fromDomain := DomainOf(m.Get("From"))
	if fromDomain != "" && idDomain != "" && !SameOrgDomain(idDomain, fromDomain) {
		// Legitimate for mail sent through an ESP, so this is informational
		// on its own and only meaningful in combination with other signals.
		add(Finding{
			Code: "HDR_MSGID_DOMAIN_MISMATCH", Severity: SeverityInfo, Header: "Message-ID",
			Message: fmt.Sprintf("Message-ID domain %q differs from From domain %q", idDomain, fromDomain),
			Score:   0.5,
		})
	}
}

// checkMIME validates the MIME framing headers.
func (m *MessageContext) checkMIME(add func(Finding)) {
	ctype := m.Get("Content-Type")
	if ctype == "" {
		return
	}

	if !m.Has("MIME-Version") {
		add(Finding{
			Code: "MIME_VERSION_MISSING", Severity: SeverityLow, Header: "MIME-Version",
			Message: "Content-Type is present but MIME-Version is not",
			Score:   1.0,
		})
	}

	mediaType, params, err := parseMediaTypeLoose(ctype)
	if err != nil {
		add(Finding{
			Code: "MIME_CONTENT_TYPE_MALFORMED", Severity: SeverityMedium, Header: "Content-Type",
			Message: fmt.Sprintf("Content-Type %q is malformed: %v", truncateStr(ctype, 60), err),
			Score:   2.0,
		})
		return
	}

	if strings.HasPrefix(mediaType, "multipart/") {
		boundary := params["boundary"]
		if boundary == "" {
			add(Finding{
				Code: "MIME_BOUNDARY_MISSING", Severity: SeverityMedium, Header: "Content-Type",
				Message: "multipart Content-Type has no boundary parameter",
				Score:   3.0,
			})
		} else if !strings.Contains(m.Body, "--"+boundary) {
			add(Finding{
				Code: "MIME_BOUNDARY_UNUSED", Severity: SeverityMedium, Header: "Content-Type",
				Message: fmt.Sprintf("declared boundary %q does not appear in the body", truncateStr(boundary, 40)),
				Score:   3.0,
			})
		}
	}

	if cte := strings.ToLower(strings.TrimSpace(m.Get("Content-Transfer-Encoding"))); cte != "" {
		switch cte {
		case "7bit", "8bit", "binary", "quoted-printable", "base64":
		default:
			add(Finding{
				Code: "MIME_CTE_UNKNOWN", Severity: SeverityLow, Header: "Content-Transfer-Encoding",
				Message: fmt.Sprintf("unrecognised Content-Transfer-Encoding %q", truncateStr(cte, 40)),
				Score:   1.0,
			})
		}
	}
}

// checkReceivedChain inspects the trace fields for the anomalies that
// indicate a forged or unusual delivery path.
func (m *MessageContext) checkReceivedChain(add func(Finding)) {
	hops := m.ReceivedChain()

	if len(hops) == 0 {
		add(Finding{
			Code: "RCVD_NONE", Severity: SeverityMedium, Header: "Received",
			Message: "message has no Received fields",
			Score:   2.0,
		})
		return
	}

	if len(hops) > maxReceivedHops {
		add(Finding{
			Code: "RCVD_EXCESSIVE", Severity: SeverityLow, Header: "Received",
			Message: fmt.Sprintf("message has %d Received hops (limit %d)", len(hops), maxReceivedHops),
			Score:   1.5,
		})
	}

	// Timestamps must not increase as we walk from the newest hop (index 0)
	// to the oldest. A reversal means a hop lied about when it handled the
	// message, or an injected field was placed out of order.
	for i := 0; i+1 < len(hops); i++ {
		newer, older := hops[i], hops[i+1]
		if !newer.HasTimestamp || !older.HasTimestamp {
			continue
		}
		// Allow a minute of clock skew between independent MTAs.
		if older.Timestamp.After(newer.Timestamp.Add(time.Minute)) {
			add(Finding{
				Code: "RCVD_TIME_REVERSED", Severity: SeverityMedium, Header: "Received",
				Message: fmt.Sprintf("Received hop %d is timestamped before hop %d", i, i+1),
				Score:   2.5,
			})
			break // one report is enough; the chain is already suspect
		}
	}

	// The oldest hop is where the message entered the visible path. A private
	// address there means either internal origin or a fabricated hop.
	oldest := hops[len(hops)-1]
	if oldest.FromIP != "" && IsPrivateIP(oldest.FromIP) && len(hops) > 1 {
		add(Finding{
			Code: "RCVD_PRIVATE_ORIGIN", Severity: SeverityLow, Header: "Received",
			Message: fmt.Sprintf("oldest Received hop originates from private address %s", oldest.FromIP),
			Score:   1.0,
		})
	}

	unparsed := 0
	for _, h := range hops {
		if h.By == "" && h.From == "" {
			unparsed++
		}
	}
	if unparsed > 0 && unparsed == len(hops) {
		add(Finding{
			Code: "RCVD_UNPARSEABLE", Severity: SeverityLow, Header: "Received",
			Message: "no Received field could be parsed into from/by clauses",
			Score:   1.0,
		})
	}
}

// checkAuthentication turns the reported SPF, DKIM and DMARC results into
// findings.
func (m *MessageContext) checkAuthentication(add func(Finding)) {
	ar := m.AuthResults()

	if !ar.Present {
		add(Finding{
			Code: "AUTH_NOT_EVALUATED", Severity: SeverityInfo,
			Message: "no Authentication-Results field; SPF, DKIM and DMARC state is unknown",
			Score:   0.5,
		})
		return
	}

	switch ar.SPF {
	case "fail":
		add(Finding{
			Code: "AUTH_SPF_FAIL", Severity: SeverityHigh, Header: "Authentication-Results",
			Message: fmt.Sprintf("SPF failed for %q", ar.SPFDomain), Score: 5.0,
		})
	case "softfail":
		add(Finding{
			Code: "AUTH_SPF_SOFTFAIL", Severity: SeverityLow, Header: "Authentication-Results",
			Message: fmt.Sprintf("SPF softfailed for %q", ar.SPFDomain), Score: 2.0,
		})
	case "permerror", "temperror":
		add(Finding{
			Code: "AUTH_SPF_ERROR", Severity: SeverityLow, Header: "Authentication-Results",
			Message: fmt.Sprintf("SPF evaluation returned %s", ar.SPF), Score: 1.0,
		})
	}

	if ar.DKIM == "fail" {
		add(Finding{
			Code: "AUTH_DKIM_FAIL", Severity: SeverityMedium, Header: "Authentication-Results",
			Message: "DKIM signature verification failed", Score: 3.5,
		})
	}
	if ar.Signed && ar.DKIM == "" {
		add(Finding{
			Code: "AUTH_DKIM_UNVERIFIED", Severity: SeverityInfo, Header: "DKIM-Signature",
			Message: "message is DKIM-signed but no verifier reported a result", Score: 0.5,
		})
	}

	switch ar.DMARC {
	case "fail":
		severity, score := SeverityHigh, 6.0
		if ar.DMARCPolicy == "none" {
			severity, score = SeverityMedium, 3.0
		}
		add(Finding{
			Code: "AUTH_DMARC_FAIL", Severity: severity, Header: "Authentication-Results",
			Message: fmt.Sprintf("DMARC failed (policy %q)", ar.DMARCPolicy), Score: score,
		})
	case "pass":
		// Nothing to report; alignment is the expected state.
	default:
		if ar.SPF == "pass" && !m.SPFAligned(false) && !m.DKIMAligned(false) {
			add(Finding{
				Code: "AUTH_NO_ALIGNMENT", Severity: SeverityMedium,
				Message: "SPF passed but neither SPF nor DKIM aligns with the From domain",
				Score:   3.0,
			})
		}
	}
}

// envelopeSender returns the envelope sender from whichever source supplied
// it, preferring the explicit field over reconstructed headers.
func (m *MessageContext) envelopeSender() string {
	if m.EnvelopeFrom != "" {
		return m.EnvelopeFrom
	}
	if len(m.EnvelopeSenders) > 0 {
		return m.EnvelopeSenders[0]
	}
	if v := m.Get("Return-Path"); v != "" {
		return strings.Trim(strings.TrimSpace(v), "<>")
	}
	if v := m.Get("X-Envelope-From"); v != "" {
		return strings.Trim(strings.TrimSpace(v), "<>")
	}
	return ""
}

// isListMail reports whether the message came through list or bulk
// infrastructure of any kind. Such senders legitimately rewrite the envelope
// sender away from the header From, so an envelope mismatch is not
// suspicious for them.
func (m *MessageContext) isListMail() bool {
	return m.Has("List-Id") || m.Has("List-Post") || m.Has("List-Unsubscribe")
}

// isDiscussionList reports whether the message was relayed by an actual
// mailing list, as opposed to a marketing blast.
//
// List-Unsubscribe alone does not qualify: bulk sender requirements have made
// it near-universal on marketing mail, so keying off it would classify every
// newsletter as a discussion list. List-Id and List-Post are the fields that
// only real list managers set.
func (m *MessageContext) isDiscussionList() bool {
	return m.Has("List-Id") || m.Has("List-Post")
}

// ReceivedChain parses and caches the Received trace fields.
func (m *MessageContext) ReceivedChain() []ReceivedHop {
	if m.hopsParsed {
		return m.receivedHops
	}

	raw := m.GetAll("Received")
	hops := make([]ReceivedHop, 0, len(raw))
	for i, r := range raw {
		hops = append(hops, parseReceivedHop(i, r))
	}
	m.receivedHops = hops
	m.hopsParsed = true
	return hops
}

// parseReceivedHop extracts the clauses of one Received field. The grammar in
// RFC 5321 section 4.4 is loose in practice, so this is a tolerant scan
// rather than a strict parse.
func parseReceivedHop(index int, raw string) ReceivedHop {
	hop := ReceivedHop{Index: index, Raw: raw}

	// The timestamp follows the last semicolon.
	body := raw
	if i := strings.LastIndex(raw, ";"); i >= 0 {
		body = raw[:i]
		if ts, err := mail.ParseDate(strings.TrimSpace(stripComments(raw[i+1:]))); err == nil {
			hop.Timestamp = ts
			hop.HasTimestamp = true
		}
	}

	// Capture bracketed IPs before comments are stripped, since the sending
	// host's real address is conventionally written inside a comment.
	hop.FromIP = firstBracketedIP(body)

	clean := stripComments(body)
	fields := strings.Fields(clean)
	for i := 0; i < len(fields); i++ {
		switch strings.ToLower(fields[i]) {
		case "from":
			if i+1 < len(fields) && hop.From == "" {
				hop.From = strings.Trim(fields[i+1], "<>")
			}
		case "by":
			if i+1 < len(fields) && hop.By == "" {
				hop.By = strings.Trim(fields[i+1], "<>")
			}
		case "with":
			if i+1 < len(fields) && hop.With == "" {
				hop.With = fields[i+1]
			}
		case "id":
			if i+1 < len(fields) && hop.ID == "" {
				hop.ID = strings.Trim(fields[i+1], "<>")
			}
		case "for":
			if i+1 < len(fields) && hop.For == "" {
				hop.For = strings.Trim(fields[i+1], "<>;")
			}
		}
	}

	if hop.FromIP == "" && hop.From != "" {
		if ip := extractIP(hop.From); ip != "" {
			hop.FromIP = ip
		}
	}

	return hop
}

// isValidFieldName reports whether a header field name consists only of
// printable US-ASCII excluding colon, as RFC 5322 ftext requires.
func isValidFieldName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if r < 33 || r > 126 || r == ':' {
			return false
		}
	}
	return true
}

// hasRawNonASCII reports whether a string contains octets above 0x7F that
// were not introduced by RFC 2047 decoding.
func hasRawNonASCII(s string) bool {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return true
		}
	}
	return false
}

// isDecodableEncodedWord reports whether every encoded-word in the value can
// be decoded. A value with no encoded-words is trivially decodable.
func isDecodableEncodedWord(s string) bool {
	_, err := wordDecoder.DecodeHeader(s)
	return err == nil
}

// extractAddressFromText finds an email address embedded in free text, such
// as a display name that claims to be an address.
func extractAddressFromText(s string) string {
	for _, field := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '<' || r == '>' || r == ',' || r == ';' || r == '"' || r == '(' || r == ')'
	}) {
		field = strings.Trim(field, ".:")
		at := strings.Index(field, "@")
		if at <= 0 || at == len(field)-1 {
			continue
		}
		if !strings.Contains(field[at+1:], ".") {
			continue
		}
		if strings.Count(field, "@") != 1 {
			continue
		}
		return field
	}
	return ""
}

func truncateStr(s string, max int) string {
	if max <= 3 || len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

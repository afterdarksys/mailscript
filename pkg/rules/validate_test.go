package rules

import (
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, raw string) *MessageContext {
	t.Helper()
	ctx, err := ParseMessage([]byte(raw))
	if err != nil {
		t.Fatalf("ParseMessage: %v", err)
	}
	ctx.Now = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	return ctx
}

func hasCode(findings []Finding, code string) bool {
	for _, f := range findings {
		if f.Code == code {
			return true
		}
	}
	return false
}

func codes(findings []Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.Code)
	}
	return out
}

const wellFormed = "From: Alice <alice@example.com>\r\n" +
	"To: Bob <bob@example.net>\r\n" +
	"Subject: Lunch\r\n" +
	"Date: Mon, 27 Jul 2026 10:00:00 +0000\r\n" +
	"Message-ID: <abc123@example.com>\r\n" +
	"MIME-Version: 1.0\r\n" +
	"Content-Type: text/plain; charset=utf-8\r\n" +
	"Received: from mail.example.com (mail.example.com [192.0.2.1]) by mx.example.net; Mon, 27 Jul 2026 10:00:05 +0000\r\n" +
	"\r\n" +
	"Are you free at one?\r\n"

func TestValidateCleanMessageHasNoSeriousFindings(t *testing.T) {
	ctx := mustParse(t, wellFormed)
	findings := ctx.ValidateHeaders()

	for _, f := range findings {
		if severityRank(f.Severity) >= severityRank(SeverityMedium) {
			t.Errorf("unexpected %s finding on a clean message: %s (%s)", f.Severity, f.Code, f.Message)
		}
	}
}

func TestValidateDetectsMissingFrom(t *testing.T) {
	ctx := mustParse(t, "To: bob@example.net\r\nSubject: Hi\r\n\r\nBody\r\n")

	if !hasCode(ctx.ValidateHeaders(), "HDR_FROM_MISSING") {
		t.Errorf("expected HDR_FROM_MISSING, got %v", codes(ctx.ValidateHeaders()))
	}
}

func TestValidateDetectsDuplicateFrom(t *testing.T) {
	raw := "From: Real <real@example.com>\r\n" +
		"From: Fake <fake@evil.example>\r\n" +
		"Subject: Hi\r\n\r\nBody\r\n"
	ctx := mustParse(t, raw)

	findings := ctx.ValidateHeaders()
	if !hasCode(findings, "HDR_DUP_FROM") {
		t.Fatalf("expected HDR_DUP_FROM, got %v", codes(findings))
	}
	for _, f := range findings {
		if f.Code == "HDR_DUP_FROM" && severityRank(f.Severity) < severityRank(SeverityHigh) {
			t.Errorf("a duplicated From should be high severity, got %s", f.Severity)
		}
	}
}

func TestValidateDetectsDisplayNameSpoof(t *testing.T) {
	raw := "From: \"billing@paypal.com\" <attacker@evil.example>\r\n" +
		"Subject: Invoice\r\n\r\nBody\r\n"
	ctx := mustParse(t, raw)

	if !hasCode(ctx.ValidateHeaders(), "SPOOF_DISPLAY_NAME_ADDR") {
		t.Errorf("expected SPOOF_DISPLAY_NAME_ADDR, got %v", codes(ctx.ValidateHeaders()))
	}
}

func TestValidateDetectsReplyToMismatch(t *testing.T) {
	raw := "From: ceo@company.example\r\n" +
		"Reply-To: ceo@attacker.example\r\n" +
		"Subject: Wire request\r\n\r\nBody\r\n"
	ctx := mustParse(t, raw)

	if !hasCode(ctx.ValidateHeaders(), "SPOOF_REPLYTO_MISMATCH") {
		t.Errorf("expected SPOOF_REPLYTO_MISMATCH, got %v", codes(ctx.ValidateHeaders()))
	}
}

func TestValidateAcceptsSubdomainReplyTo(t *testing.T) {
	raw := "From: ceo@company.example\r\n" +
		"Reply-To: ceo@mail.company.example\r\n" +
		"Subject: Hi\r\n\r\nBody\r\n"
	ctx := mustParse(t, raw)

	if hasCode(ctx.ValidateHeaders(), "SPOOF_REPLYTO_MISMATCH") {
		t.Error("a same-organisation Reply-To must not be flagged")
	}
}

func TestValidateDetectsHeaderInjection(t *testing.T) {
	ctx := NewMessageContext()
	ctx.SetHeaders([]Header{
		{Name: "From", Value: "a@example.com"},
		{Name: "Subject", Value: "Hi\r\nBcc: victim@example.net"},
	})

	findings := ctx.ValidateHeaders()
	if !hasCode(findings, "HDR_INJECTION") {
		t.Fatalf("expected HDR_INJECTION, got %v", codes(findings))
	}
	for _, f := range findings {
		if f.Code == "HDR_INJECTION" && f.Severity != SeverityCritical {
			t.Errorf("header injection should be critical, got %s", f.Severity)
		}
	}
}

func TestValidateDetectsBadDates(t *testing.T) {
	future := "From: a@example.com\r\nDate: Mon, 27 Jul 2027 10:00:00 +0000\r\n\r\nBody\r\n"
	if !hasCode(mustParse(t, future).ValidateHeaders(), "HDR_DATE_FUTURE") {
		t.Error("expected HDR_DATE_FUTURE")
	}

	garbage := "From: a@example.com\r\nDate: not a date\r\n\r\nBody\r\n"
	if !hasCode(mustParse(t, garbage).ValidateHeaders(), "HDR_DATE_UNPARSEABLE") {
		t.Error("expected HDR_DATE_UNPARSEABLE")
	}
}

func TestValidateDetectsMalformedMessageID(t *testing.T) {
	raw := "From: a@example.com\r\nMessage-ID: no-brackets-here\r\n\r\nBody\r\n"

	if !hasCode(mustParse(t, raw).ValidateHeaders(), "HDR_MSGID_MALFORMED") {
		t.Error("expected HDR_MSGID_MALFORMED")
	}
}

func TestValidateDetectsMixedScriptDomain(t *testing.T) {
	// "pаypal" with a Cyrillic 'а'.
	raw := "From: security@pаypal.example\r\nSubject: Verify\r\n\r\nBody\r\n"
	ctx := mustParse(t, raw)

	if !hasCode(ctx.ValidateHeaders(), "SPOOF_DOMAIN_MIXED_SCRIPT") {
		t.Errorf("expected SPOOF_DOMAIN_MIXED_SCRIPT, got %v", codes(ctx.ValidateHeaders()))
	}
}

func TestValidateDetectsMultipartWithoutBoundary(t *testing.T) {
	raw := "From: a@example.com\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed\r\n\r\nBody\r\n"

	if !hasCode(mustParse(t, raw).ValidateHeaders(), "MIME_BOUNDARY_MISSING") {
		t.Error("expected MIME_BOUNDARY_MISSING")
	}
}

func TestValidateFindingsAreSortedBySeverity(t *testing.T) {
	raw := "From: Real <real@example.com>\r\n" +
		"From: Fake <fake@evil.example>\r\n\r\nBody\r\n"
	findings := mustParse(t, raw).ValidateHeaders()

	for i := 1; i < len(findings); i++ {
		if severityRank(findings[i].Severity) > severityRank(findings[i-1].Severity) {
			t.Fatalf("findings are not sorted by descending severity: %v", codes(findings))
		}
	}
}

// -- Header access ----------------------------------------------------------

func TestHeaderLookupIsCaseInsensitive(t *testing.T) {
	ctx := mustParse(t, wellFormed)

	for _, name := range []string{"From", "from", "FROM", "FrOm"} {
		if got := ctx.Get(name); !strings.Contains(got, "alice@example.com") {
			t.Errorf("Get(%q) returned %q", name, got)
		}
	}
}

func TestGetAllReturnsEveryOccurrence(t *testing.T) {
	raw := "Received: hop one\r\nReceived: hop two\r\nFrom: a@example.com\r\n\r\nBody\r\n"
	ctx := mustParse(t, raw)

	if got := ctx.GetAll("Received"); len(got) != 2 {
		t.Fatalf("expected two Received values, got %v", got)
	}
	if ctx.Count("received") != 2 {
		t.Errorf("expected count 2, got %d", ctx.Count("received"))
	}
}

func TestFoldedHeadersAreUnfolded(t *testing.T) {
	raw := "From: a@example.com\r\nSubject: this subject\r\n is folded across lines\r\n\r\nBody\r\n"
	ctx := mustParse(t, raw)

	if got := ctx.Get("Subject"); got != "this subject is folded across lines" {
		t.Errorf("unexpected unfolded subject: %q", got)
	}
}

// -- Received chain ---------------------------------------------------------

func TestReceivedChainParsing(t *testing.T) {
	ctx := mustParse(t, wellFormed)
	hops := ctx.ReceivedChain()

	if len(hops) != 1 {
		t.Fatalf("expected one hop, got %d", len(hops))
	}
	if hops[0].FromIP != "192.0.2.1" {
		t.Errorf("expected the bracketed IP to be extracted, got %q", hops[0].FromIP)
	}
	if !hops[0].HasTimestamp {
		t.Error("expected the hop timestamp to be parsed")
	}
	if hops[0].By != "mx.example.net;" && hops[0].By != "mx.example.net" {
		t.Errorf("unexpected by clause: %q", hops[0].By)
	}
}

func TestReceivedTimeReversalIsDetected(t *testing.T) {
	raw := "From: a@example.com\r\n" +
		"Received: from b by c; Mon, 27 Jul 2026 09:00:00 +0000\r\n" +
		"Received: from d by e; Mon, 27 Jul 2026 11:00:00 +0000\r\n" +
		"\r\nBody\r\n"

	if !hasCode(mustParse(t, raw).ValidateHeaders(), "RCVD_TIME_REVERSED") {
		t.Error("expected RCVD_TIME_REVERSED when the newest hop predates the older one")
	}
}

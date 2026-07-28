package rules

import (
	"strings"
	"testing"
)

func TestHumanMailIsClassifiedHuman(t *testing.T) {
	raw := "From: Alice <alice@example.com>\r\n" +
		"To: Bob <bob@example.net>\r\n" +
		"Subject: Re: Lunch on Thursday\r\n" +
		"In-Reply-To: <prev@example.net>\r\n" +
		"References: <prev@example.net>\r\n" +
		"Message-ID: <reply@example.com>\r\n" +
		"X-Mailer: Apple Mail (2.3731.700.6)\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		"Thursday works for me.\r\n\r\nOn Monday, Bob wrote:\r\n> How about lunch?\r\n"

	ctx := mustParse(t, raw)
	assessment := ctx.AssessHuman()

	if assessment.Class != ClassHuman {
		t.Fatalf("expected human, got %s (score %.0f)\n%s",
			assessment.Class, assessment.Score, strings.Join(assessment.Reasons, "\n"))
	}
	if !ctx.IsHuman() {
		t.Error("IsHuman should be true")
	}
	if ctx.IsAutomated() {
		t.Error("IsAutomated should be false")
	}
}

func TestMarketingMailIsClassifiedBulk(t *testing.T) {
	raw := "From: Deals <no-reply@shop.example>\r\n" +
		"To: customer@example.net\r\n" +
		"Subject: 50% OFF EVERYTHING\r\n" +
		"List-Unsubscribe: <https://shop.example/u/123>\r\n" +
		"Precedence: bulk\r\n" +
		"X-Campaign-Id: summer-2026\r\n" +
		"X-Mailer: Mailchimp\r\n" +
		"Content-Type: text/html\r\n" +
		"\r\n" +
		"<html><body><h1>Sale</h1>" +
		"<img src=\"https://track.example/p.gif\" width=\"1\" height=\"1\">" +
		"<a href=\"https://shop.example/u\">Unsubscribe</a> or view in browser</body></html>\r\n"

	ctx := mustParse(t, raw)
	assessment := ctx.AssessHuman()

	if assessment.Class != ClassBulk {
		t.Fatalf("expected bulk, got %s (score %.0f)", assessment.Class, assessment.Score)
	}
	if !ctx.IsBulk() || !ctx.IsAutomated() {
		t.Error("bulk mail should be both bulk and automated")
	}
	if assessment.Score > 40 {
		t.Errorf("bulk mail should score low on the human scale, got %.0f", assessment.Score)
	}
	if ctx.TrackingPixelCount() != 1 {
		t.Errorf("expected one tracking pixel, got %d", ctx.TrackingPixelCount())
	}
}

func TestMailingListIsClassifiedList(t *testing.T) {
	raw := "From: Contributor <dev@example.org>\r\n" +
		"To: list@lists.example.org\r\n" +
		"Subject: Re: patch review\r\n" +
		"List-Id: <dev.lists.example.org>\r\n" +
		"List-Post: <mailto:dev@lists.example.org>\r\n" +
		"In-Reply-To: <x@example.org>\r\n" +
		"\r\nLooks good to me.\r\n"

	ctx := mustParse(t, raw)
	if got := ctx.AssessHuman().Class; got != ClassList {
		t.Fatalf("expected list, got %s", got)
	}
	if !ctx.isListMail() {
		t.Error("isListMail should be true")
	}
}

func TestAutoReplyIsClassifiedAutomated(t *testing.T) {
	raw := "From: Alice <alice@example.com>\r\n" +
		"To: bob@example.net\r\n" +
		"Subject: Out of office\r\n" +
		"Auto-Submitted: auto-replied\r\n" +
		"\r\nI am away until August.\r\n"

	ctx := mustParse(t, raw)
	if got := ctx.AssessHuman().Class; got != ClassAutomated {
		t.Fatalf("expected automated, got %s", got)
	}
}

func TestTransactionalMailIsDistinguishedFromBulk(t *testing.T) {
	raw := "From: Receipts <no-reply@store.example>\r\n" +
		"To: customer@example.net\r\n" +
		"Subject: Your order 12345\r\n" +
		"Message-ID: <order-12345@store.example>\r\n" +
		"Content-Type: text/plain\r\n" +
		"\r\nThank you for your order. Total: 42.00.\r\n"

	ctx := mustParse(t, raw)
	class := ctx.AssessHuman().Class

	// It is machine-written, but addressed to this recipient alone with no
	// campaign infrastructure behind it.
	if class != ClassTransactional {
		t.Fatalf("expected transactional, got %s", class)
	}
	if ctx.IsBulk() {
		t.Error("transactional mail is not bulk")
	}
	if !ctx.IsAutomated() {
		t.Error("transactional mail is still automated")
	}
}

func TestHumanSignalsAreReported(t *testing.T) {
	raw := "From: Alice <alice@example.com>\r\n" +
		"To: bob@example.net\r\n" +
		"Subject: Re: hello\r\n" +
		"In-Reply-To: <x@example.net>\r\n" +
		"\r\nHi Bob, see attached.\r\n"

	assessment := mustParse(t, raw).AssessHuman()

	var found bool
	for _, s := range assessment.Signals {
		if s.Name == "threaded" {
			found = true
			if s.Weight <= 0 {
				t.Errorf("threading should favour human, weight %v", s.Weight)
			}
		}
	}
	if !found {
		t.Error("expected a threaded signal")
	}
	if len(assessment.Reasons) == 0 {
		t.Error("expected human-readable reasons")
	}
}

func TestGenericGreetingIsNotPersonal(t *testing.T) {
	if hasPersonalGreeting("dear valued customer, you have won") {
		t.Error("a bulk salutation must not count as a personal greeting")
	}
	if !hasPersonalGreeting("hi rachel,\nabout tomorrow") {
		t.Error("a named greeting should count as personal")
	}
}

func TestNoReplyDetection(t *testing.T) {
	for _, local := range []string{"no-reply", "noreply", "do-not-reply", "donotreply", "mailer-daemon", "bounces+abc"} {
		if !noReplyPattern.MatchString(local) {
			t.Errorf("%q should be recognised as an unattended mailbox", local)
		}
	}
	for _, local := range []string{"alice", "rachel.chen", "support"} {
		if noReplyPattern.MatchString(local) {
			t.Errorf("%q should not be treated as unattended", local)
		}
	}
}

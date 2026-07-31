package main

import (
	"strings"
	"testing"
	"time"
)

func TestStripHeaderRemovesClientQuarantineMarker(t *testing.T) {
	raw := []byte("From: sender@example.net\r\nX-MailScript-Quarantine: true\r\nSubject: test\r\n\r\nbody\r\n")
	got := string(stripHeader(raw, "x-mailscript-quarantine"))
	want := "From: sender@example.net\r\nSubject: test\r\n\r\nbody\r\n"
	if got != want {
		t.Fatalf("stripHeader() = %q, want %q", got, want)
	}
}

func TestApplyModifiedHeadersPrependsTrustedPolicyHeader(t *testing.T) {
	raw := []byte("Subject: test\r\n\r\nbody\r\n")
	got := string(applyModifiedHeaders(raw, map[string]string{"X-Gomeow-Mail-Class": "transactional"}))
	if got != "X-Gomeow-Mail-Class: transactional\r\nSubject: test\r\n\r\nbody\r\n" {
		t.Fatalf("unexpected message: %q", got)
	}
}

func TestApplyHeaderChangesRemovesAllOccurrencesAndContinuations(t *testing.T) {
	raw := []byte("Received: from private.example\r\n\tby relay.example\r\nX-Originating-IP: 192.0.2.1\r\nSubject: keep\r\n\r\nbody")
	got := string(applyHeaderChanges(raw, []string{"Received", "X-Originating-IP"}, nil))
	if strings.Contains(got, "private.example") || strings.Contains(got, "192.0.2.1") {
		t.Fatalf("metadata was not removed: %q", got)
	}
	if !strings.Contains(got, "Subject: keep") || !strings.Contains(got, "\r\n\r\nbody") {
		t.Fatalf("message was damaged: %q", got)
	}
}

func TestSMTPProxyRejectsDuplicateFromEndToEnd(t *testing.T) {
	proxy := &SMTPProxy{
		script: `
def evaluate():
    if has_finding("HDR_DUP_FROM"):
        drop()
        return
    accept()
`,
		stats: &ProxyStats{StartTime: time.Now()},
	}
	session := &SMTPSession{
		proxy:      proxy,
		from:       "sender@example.com",
		recipients: []string{"recipient@example.net"},
		data:       []byte("From: Real <sender@example.com>\r\nFrom: Fake <attacker@example.net>\r\nSubject: test\r\n\r\nbody\r\n"),
	}
	accepted, _, reason := session.processWithMailScript()
	if accepted || !strings.Contains(reason, "dropped") {
		t.Fatalf("duplicate From was not rejected: accepted=%v reason=%q", accepted, reason)
	}
}

func TestDotStuff(t *testing.T) {
	got := string(dotStuff([]byte("first\r\n.second\r\n..third\r\n")))
	if got != "first\r\n..second\r\n...third\r\n" {
		t.Fatalf("unexpected dot stuffing: %q", got)
	}
}

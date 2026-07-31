package main

import "testing"

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

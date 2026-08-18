package main

import (
	"bufio"
	"errors"
	"fmt"
	"net"
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

func TestReadSMTPReplyParsesCodeAndFollowsContinuations(t *testing.T) {
	single := bufio.NewReader(strings.NewReader("250 OK\r\n"))
	code, _, err := readSMTPReply(single)
	if err != nil || code != 250 {
		t.Fatalf("single-line: code=%d err=%v, want 250/nil", code, err)
	}

	// Multi-line reply: only the final line (space after code) ends it.
	multi := bufio.NewReader(strings.NewReader("250-first\r\n250-second\r\n250 done\r\n"))
	code, full, err := readSMTPReply(multi)
	if err != nil || code != 250 {
		t.Fatalf("multi-line: code=%d err=%v, want 250/nil", code, err)
	}
	if !strings.Contains(full, "first") || !strings.Contains(full, "done") {
		t.Fatalf("multi-line reply not fully consumed: %q", full)
	}
}

func TestUpstreamErrorMessageStripsLeadingCode(t *testing.T) {
	e := &upstreamError{code: 554, stage: "RCPT TO", text: "554 5.7.1 Relay access denied\r\n"}
	if got := e.clientReply(); got != "554 5.7.1 Relay access denied" {
		t.Fatalf("clientReply() = %q, want %q", got, "554 5.7.1 Relay access denied")
	}
}

// The regression this whole change exists for: an upstream that rejects the
// recipient with a permanent 554 must reach the client as 554, not a
// downgraded 450 that makes the sender's MTA retry for days.
func TestForwardSurfacesUpstreamRcptRejectionWithRealCode(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		r := bufio.NewReader(conn)
		fmt.Fprintf(conn, "220 fake ready\r\n")
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			switch {
			case strings.HasPrefix(line, "EHLO"):
				fmt.Fprintf(conn, "250 fake\r\n")
			case strings.HasPrefix(line, "MAIL FROM"):
				fmt.Fprintf(conn, "250 OK\r\n")
			case strings.HasPrefix(line, "RCPT TO"):
				fmt.Fprintf(conn, "554 5.7.1 Relay access denied\r\n")
			case strings.HasPrefix(line, "QUIT"):
				fmt.Fprintf(conn, "221 bye\r\n")
				return
			default:
				fmt.Fprintf(conn, "250 OK\r\n")
			}
		}
	}()

	s := &SMTPSession{
		from:       "noreply@afterdarksys.com",
		recipients: []string{"stranger@gmail.com"},
		data:       []byte("Subject: x\r\n\r\nbody\r\n"),
		proxy:      &SMTPProxy{upstreamServer: ln.Addr().String()},
	}

	err = s.forwardToUpstream()
	if err == nil {
		t.Fatal("expected an error when upstream rejects the only recipient")
	}
	var ue *upstreamError
	if !errors.As(err, &ue) {
		t.Fatalf("expected *upstreamError, got %T: %v", err, err)
	}
	if ue.code != 554 {
		t.Fatalf("upstream code = %d, want 554 (must not be downgraded to 450)", ue.code)
	}
	if ue.stage != "RCPT TO" {
		t.Fatalf("stage = %q, want RCPT TO", ue.stage)
	}
}

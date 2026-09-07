package main

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

// Exercise the public Starlark actions through policy evaluation and real SMTP
// delivery. Monitoring destinations belong only in the envelope, never DATA.
func TestComplianceRouting(t *testing.T) {
	const raw = "From: sender@example.com\r\nTo: original@example.com\r\nCc: colleague@example.com\r\nSubject: confidential\r\nContent-Type: text/plain\r\n\r\noriginal body\r\n"
	for _, tc := range []struct {
		name, script string
		want         []string
		failure      bool
	}{
		{"divert", `divert_to("admin@example.com")`, []string{"admin@example.com"}, false},
		{"screen", `screen_to("monitor@example.com")`, []string{"original@example.com", "colleague@example.com", "monitor@example.com"}, false},
		{"multiple_monitors", "screen_to(\"monitor@example.com\")\nscreen_to(\"monitor@example.com\")\nscreen_to(\"second@example.com\")", []string{"original@example.com", "colleague@example.com", "monitor@example.com", "second@example.com"}, false},
		{"divert_and_screen", "divert_to(\"admin@example.com\")\nscreen_to(\"monitor@example.com\")", []string{"admin@example.com", "monitor@example.com"}, false},
		{"unavailable_monitor", `screen_to("bad@example.com")`, nil, true},
		{"unavailable_diversion", `divert_to("bad@example.com")`, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := testBackend(t, "plain", false)
			p := &SMTPProxy{upstreamServer: backend.address, script: tc.script, stats: &ProxyStats{}}
			s := &SMTPSession{proxy: p, from: "sender@example.com", recipients: []string{"original@example.com", "colleague@example.com"}, data: []byte(raw)}
			if ok, _, reason := s.processWithMailScript(); !ok {
				t.Fatalf("policy refused: %s", reason)
			}
			err := s.deliver(context.Background())
			if (err != nil) != tc.failure {
				t.Fatalf("delivery error = %v; failure wanted = %v", err, tc.failure)
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			if tc.failure {
				if len(backend.messages) != 0 {
					t.Fatal("delivered DATA despite required recipient rejection")
				}
				return
			}
			if len(backend.messages) != 1 || backend.messages[0] != raw {
				t.Fatalf("visible headers/body changed: %q", backend.messages)
			}
			var recipients []string
			for _, command := range backend.commands {
				if strings.HasPrefix(command, "RCPT TO:<") {
					recipients = append(recipients, strings.TrimSuffix(strings.TrimPrefix(command, "RCPT TO:<"), ">\r\n"))
				}
			}
			if !reflect.DeepEqual(recipients, tc.want) {
				t.Fatalf("recipients = %v, want %v", recipients, tc.want)
			}
		})
	}
}

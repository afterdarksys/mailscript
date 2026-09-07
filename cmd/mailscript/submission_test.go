package main

import (
	"bufio"
	"encoding/base64"
	"net"
	"testing"
	"time"
)

func TestSubmissionAuthenticationUsesEncryptedBackend(t *testing.T) {
	backend := testBackend(t, "starttls", true)
	for _, tc := range []struct {
		password string
		tls      bool
		want     int
	}{{"password", true, 235}, {"wrong", true, 535}, {"password", false, 538}} {
		server, client := net.Pipe()
		client.SetDeadline(time.Now().Add(5 * time.Second))
		s := &SMTPSession{conn: server, reader: bufio.NewReader(server), helo: "client", tlsActive: tc.tls, proxy: &SMTPProxy{submission: true, upstreamServer: backend.address, upstreamConfig: backend.config}}
		done := make(chan struct{})
		go func() {
			defer close(done)
			s.handleAUTH([]string{"AUTH", "PLAIN", base64.StdEncoding.EncodeToString([]byte("\x00user\x00" + tc.password))})
		}()
		code, _, err := readSMTPReply(bufio.NewReader(client))
		client.Close()
		server.Close()
		<-done
		if err != nil || code != tc.want {
			t.Fatalf("got %d %v want %d", code, err, tc.want)
		}
		if s.authenticated != (tc.want == 235) {
			t.Fatal("incorrect authentication state")
		}
	}
}

package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// Controlled backend supports TLS, AUTH, and per-recipient refusal. All data
// observations are synchronized so this fixture also runs under the race detector.
type backendFixture struct {
	address  string
	config   upstreamConfig
	mu       sync.Mutex
	messages []string
	commands []string
}

func testBackend(t *testing.T, mode string, authenticate bool) *backendFixture {
	t.Helper()
	certServer := httptest.NewTLSServer(nil)
	cert := certServer.TLS.Certificates[0]
	certServer.Close()
	parsed, _ := x509.ParseCertificate(cert.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	fixture := &backendFixture{address: listener.Addr().String(), config: upstreamConfig{mode: mode, roots: roots}}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	var wg sync.WaitGroup
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func(conn net.Conn) {
				defer wg.Done()
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				encrypted := mode == "tls"
				if encrypted {
					tc := tls.Server(conn, tlsConfig)
					if tc.Handshake() != nil {
						return
					}
					conn = tc
				}
				reader := bufio.NewReader(conn)
				fmt.Fprint(conn, "220 fixture\r\n")
				authed := !authenticate
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					fixture.mu.Lock()
					fixture.commands = append(fixture.commands, line)
					fixture.mu.Unlock()
					switch {
					case strings.HasPrefix(line, "EHLO"):
						fmt.Fprint(conn, "250-fixture\r\n")
						if mode == "starttls" && !encrypted {
							fmt.Fprint(conn, "250-STARTTLS\r\n")
						}
						fmt.Fprint(conn, "250 AUTH PLAIN\r\n")
					case line == "STARTTLS\r\n":
						fmt.Fprint(conn, "220 begin TLS\r\n")
						tc := tls.Server(conn, tlsConfig)
						if tc.Handshake() != nil {
							return
						}
						conn = tc
						reader = bufio.NewReader(tc)
						encrypted = true
					case strings.HasPrefix(line, "AUTH PLAIN "):
						want := base64.StdEncoding.EncodeToString([]byte("\x00user\x00password"))
						if encrypted && strings.TrimSpace(strings.TrimPrefix(line, "AUTH PLAIN ")) == want {
							authed = true
							fmt.Fprint(conn, "235 authenticated\r\n")
						} else {
							fmt.Fprint(conn, "535 bad credentials\r\n")
						}
					case strings.HasPrefix(line, "MAIL"):
						if authed {
							fmt.Fprint(conn, "250 sender\r\n")
						} else {
							fmt.Fprint(conn, "530 authenticate\r\n")
						}
					case strings.HasPrefix(line, "RCPT"):
						if strings.Contains(line, "bad@example.com") {
							fmt.Fprint(conn, "550 unknown recipient\r\n")
						} else {
							fmt.Fprint(conn, "250 recipient\r\n")
						}
					case line == "DATA\r\n":
						fmt.Fprint(conn, "354 send\r\n")
						var message strings.Builder
						for {
							line, err = reader.ReadString('\n')
							if err != nil {
								return
							}
							if line == ".\r\n" {
								break
							}
							message.WriteString(line)
						}
						fixture.mu.Lock()
						fixture.messages = append(fixture.messages, message.String())
						fixture.mu.Unlock()
						fmt.Fprint(conn, "250 queued\r\n")
					default:
						fmt.Fprint(conn, "250 ok\r\n")
					}
				}
			}(conn)
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done; wg.Wait() })
	return fixture
}

func TestUpstreamEncryptionAndAuthentication(t *testing.T) {
	for _, mode := range []string{"starttls", "tls"} {
		t.Run(mode, func(t *testing.T) {
			backend := testBackend(t, mode, true)
			cfg := backend.config
			cfg.username = "user"
			cfg.password = "password"
			s := &SMTPSession{proxy: &SMTPProxy{upstreamServer: backend.address, upstreamConfig: cfg}, from: "", recipients: []string{"good@example.com"}, data: []byte("Subject: x\r\n\r\nbody\r\n")}
			if err := s.forwardToUpstream(); err != nil {
				t.Fatal(err)
			}
			backend.mu.Lock()
			defer backend.mu.Unlock()
			if len(backend.messages) != 1 {
				t.Fatal("message missing")
			}
		})
	}
}

func TestRequiredTLSRejectsDowngradeAndBadCertificate(t *testing.T) {
	backend := testBackend(t, "plain", false)
	s := &SMTPSession{proxy: &SMTPProxy{upstreamServer: backend.address, upstreamConfig: upstreamConfig{mode: "starttls"}}}
	if _, err := s.connectUpstream(); err == nil {
		t.Fatal("STARTTLS downgrade accepted")
	}
	secure := testBackend(t, "tls", false)
	s.proxy = &SMTPProxy{upstreamServer: secure.address, upstreamConfig: upstreamConfig{mode: "tls"}}
	if _, err := s.connectUpstream(); err == nil {
		t.Fatal("untrusted certificate accepted")
	}
}

func TestSMTPRejectsIndividualRecipientsBeforeDATA(t *testing.T) {
	backend := testBackend(t, "plain", false)
	server, client := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	p := &SMTPProxy{upstreamServer: backend.address, script: "def evaluate():\n    accept()\n", stats: &ProxyStats{ActiveConnections: 1}}
	done := make(chan struct{})
	go func() { defer close(done); p.handleSMTPConnection(server) }()
	defer func() { client.Close(); <-done }()
	reader := bufio.NewReader(client)
	expect := func(want int) {
		t.Helper()
		code, _, err := readSMTPReply(reader)
		if err != nil || code != want {
			t.Fatalf("got %d %v want %d", code, err, want)
		}
	}
	send := func(line string, want int) { t.Helper(); fmt.Fprint(client, line+"\r\n"); expect(want) }
	expect(220)
	send("EHLO client", 250)
	send("MAIL FROM:<>", 250)
	send("RCPT TO:<bad@example.com>", 550)
	send("RCPT TO:<good@example.com>", 250)
	send("DATA", 354)
	send("Subject: test\r\n\r\nbody\r\n.", 250)
	send("QUIT", 221)
	backend.mu.Lock()
	defer backend.mu.Unlock()
	if len(backend.messages) != 1 {
		t.Fatal("valid recipient not delivered")
	}
	mailCommands := 0
	for _, line := range backend.commands {
		if strings.HasPrefix(line, "MAIL FROM:") {
			mailCommands++
		}
	}
	if mailCommands != 1 {
		t.Fatal("backend transaction reopened after recipient validation")
	}
}

func TestNativeRedirectReplacesEnvelope(t *testing.T) {
	backend := testBackend(t, "plain", false)
	s := &SMTPSession{proxy: &SMTPProxy{upstreamServer: backend.address}, from: "", recipients: []string{"original@example.com"}, actions: []string{"redirect:new@example.com", "screen_to:copy@example.com"}, data: []byte("Subject: x\r\n\r\nbody\r\n")}
	if err := s.deliver(context.Background()); err != nil {
		t.Fatal(err)
	}
	backend.mu.Lock()
	defer backend.mu.Unlock()
	transcript := strings.Join(backend.commands, "")
	if strings.Contains(transcript, "original@example.com") || !strings.Contains(transcript, "new@example.com") || !strings.Contains(transcript, "copy@example.com") {
		t.Fatal(transcript)
	}
}

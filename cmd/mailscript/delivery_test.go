package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	pb "github.com/afterdarksys/mailscript/pkg/proto"
)

func TestPolicyDispositionAcrossAdapters(t *testing.T) {
	for _, tc := range []struct {
		script string
		code   int
	}{
		{"accept()", 250}, {"reject()", 550}, {"defer()", 451},
		{`reply_with_smtp_error(452, "retry")`, 452},
		{"reject()\n    accept()", 550},
	} {
		t.Run(tc.script, func(t *testing.T) {
			p := &SMTPProxy{script: "def evaluate():\n    " + tc.script + "\n", stats: &ProxyStats{}}
			s := &SMTPSession{proxy: p, data: []byte("From: a@example.com\r\n\r\nbody\r\n")}
			accepted, _, _ := s.processWithMailScript()
			if s.replyCode != tc.code || accepted != (tc.code == 250) {
				t.Fatalf("SMTP got %d/%v", s.replyCode, accepted)
			}
			resp, err := (&MailScriptServiceServer{proxy: p}).ProcessMessage(context.Background(), &pb.ProcessRequest{Headers: map[string]string{"From": "a@example.com"}, Body: "body"})
			if err != nil || resp.Accepted != (tc.code == 250) {
				t.Fatalf("gRPC got %v, %v", resp, err)
			}
		})
	}
}

func TestSMTPTransactionAndTransparency(t *testing.T) {
	// Real client conversation over an in-memory connection, including two
	// transactions, a null reverse path, and SMTP transparency on input.
	server, client := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	p := &SMTPProxy{script: `def evaluate():
    if envelope_from() == "" and ".dot" in get_body():
        defer()
    else:
        reject()
`, stats: &ProxyStats{ActiveConnections: 1}}
	done := make(chan struct{})
	go func() { defer close(done); p.handleSMTPConnection(server) }()
	defer func() { client.Close(); <-done }()
	reader := bufio.NewReader(client)
	reply := func(want int) {
		t.Helper()
		code, _, err := readSMTPReply(reader)
		if err != nil || code != want {
			t.Fatalf("reply %d, %v; want %d", code, err, want)
		}
	}
	send := func(command string, want int) { t.Helper(); fmt.Fprint(client, command+"\r\n"); reply(want) }
	reply(220)
	send("RCPT TO:<b@example.com>", 503)
	send("MAIL FROM:<>", 503)
	send("EHLO client.example", 250)
	send("MAIL FROM:<>", 250)
	send("MAIL FROM:<a@example.com>", 503)
	send("RCPT TO:<b@example.com>", 250)
	send("DATA", 354)
	send("From: a@example.com\r\n\r\n..dot\r\n.", 451)
	send("DATA", 503)
	send("MAIL FROM:<a@example.com>", 250)
	send("RCPT TO:<b@example.com>", 250)
	send("DATA", 354)
	send("From: a@example.com\r\n\r\nbody\r\n.", 550)
	send("QUIT", 221)
}

func TestEnvelopeInjectionAndMalformedPaths(t *testing.T) {
	for _, line := range []string{"MAIL TO:<x>", "MAIL FROM:>x<", "MAIL FROM:<x\r\nRCPT TO:y>", "MAIL FROM:<x> SMTPUTF8"} {
		if _, err := parseSMTPPath(line, "MAIL FROM:", true); err == nil {
			t.Errorf("accepted %q", line)
		}
	}
	if _, err := parseSMTPPath("MAIL FROM:<>", "MAIL FROM:", true); err != nil {
		t.Fatal(err)
	}
	if err := validateEnvelope("", []string{"b@example.com"}); err != nil {
		t.Fatal(err)
	}
	if err := validateEnvelope("a@example.com\r\nRCPT TO:<victim>", []string{"b@example.com"}); err == nil {
		t.Fatal("accepted injection")
	}
	if got := smtpReplyText("bad\r\n250 OK\x00"); strings.ContainsAny(got, "\r\n\x00") {
		t.Fatal(got)
	}
}

func TestMalformedSMTPReplies(t *testing.T) {
	for _, input := range []string{"hello\r\n", "250-one\r\n550 two\r\n", "250?bad\r\n", strings.Repeat("x", 5000) + "\r\n"} {
		if _, _, err := readSMTPReply(bufio.NewReader(strings.NewReader(input))); err == nil {
			t.Errorf("accepted malformed reply")
		}
	}
}

func TestUpstreamRecipientFailuresNeverSendDATA(t *testing.T) {
	for _, firstCode := range []int{250, 450} {
		t.Run(fmt.Sprint(firstCode), func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			commands := make(chan []string, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					commands <- nil
					return
				}
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				r := bufio.NewReader(conn)
				fmt.Fprint(conn, "220 ready\r\n")
				var got []string
				defer func() { commands <- got }()
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					got = append(got, line)
					switch {
					case strings.Contains(line, "bad@example.com"):
						fmt.Fprint(conn, "550 no mailbox\r\n")
					case strings.HasPrefix(line, "RCPT TO"):
						fmt.Fprintf(conn, "%d first recipient\r\n", firstCode)
					default:
						fmt.Fprint(conn, "250 OK\r\n")
					}
				}
			}()
			s := &SMTPSession{proxy: &SMTPProxy{upstreamServer: listener.Addr().String()}, from: "", recipients: []string{"good@example.com", "bad@example.com"}, data: []byte("Subject: test\r\n\r\nbody\r\n")}
			err = s.forwardToUpstream()
			ue, ok := err.(*upstreamError)
			want := 451
			if firstCode == 450 {
				want = 450
			}
			if !ok || ue.code != want {
				t.Fatalf("got %v", err)
			}
			for _, command := range <-commands {
				if strings.HasPrefix(command, "DATA") {
					t.Fatal("partial message delivered")
				}
			}
		})
	}
}

func TestUnsupportedDeliveryActionsDefer(t *testing.T) {
	s := &SMTPSession{proxy: &SMTPProxy{script: "def evaluate():\n    fileinto(\"Inbox\")\n"}, data: []byte("Subject: x\r\n\r\nbody")}
	accepted, _, _ := s.processWithMailScript()
	if accepted || s.replyCode != 451 {
		t.Fatalf("unsupported action was ignored")
	}
}

func TestGRPCRawMessagePreservesDuplicatesAndReturnsEdits(t *testing.T) {
	raw := []byte("From: first@example.com\r\nFrom: second@example.com\r\nX-Private: secret\r\n\r\n.dot\r\n")
	p := &SMTPProxy{script: `def evaluate():
    if header_count("From") != 2:
        reject()
        return
    remove_header("X-Private")
    add_header("X-Filtered", "yes")
    accept()
`, stats: &ProxyStats{}}
	resp, err := (&MailScriptServiceServer{proxy: p}).ProcessMessage(context.Background(), &pb.ProcessRequest{RawMessage: raw, ClientIp: "192.0.2.1", Helo: "sender.example"})
	if err != nil || !resp.Accepted || resp.SmtpCode != 250 || resp.Forwarded {
		t.Fatalf("%v, %v", resp, err)
	}
	if len(resp.RemovedHeaders) != 1 || strings.Contains(string(resp.ProcessedMessage), "secret") || !strings.Contains(string(resp.ProcessedMessage), "X-Filtered: yes\r\n") {
		t.Fatalf("edits missing: %v", resp)
	}
	if !strings.HasSuffix(string(resp.ProcessedMessage), "\r\n\r\n.dot\r\n") {
		t.Fatal("body bytes changed")
	}
	if _, err := grpcMessage(&pb.ProcessRequest{RawMessage: raw, Body: "ambiguous"}); err == nil {
		t.Fatal("mixed input accepted")
	}
}

func TestGRPCForwardsQuarantineWithNullSender(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	messages := make(chan string, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			messages <- ""
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		r := bufio.NewReader(conn)
		fmt.Fprint(conn, "220 ready\r\n")
		var transcript strings.Builder
		defer func() { messages <- transcript.String() }()
		for {
			line, err := r.ReadString('\n')
			if err != nil {
				return
			}
			transcript.WriteString(line)
			if line == "DATA\r\n" {
				fmt.Fprint(conn, "354 send\r\n")
				for {
					line, err = r.ReadString('\n')
					if err != nil {
						return
					}
					transcript.WriteString(line)
					if line == ".\r\n" {
						break
					}
				}
				fmt.Fprint(conn, "250 queued\r\n")
			} else if line == "QUIT\r\n" {
				return
			} else {
				fmt.Fprint(conn, "250 OK\r\n")
			}
		}
	}()
	p := &SMTPProxy{script: "def evaluate():\n    quarantine()\n", forwardQuarantine: true, upstreamServer: listener.Addr().String(), stats: &ProxyStats{}}
	resp, err := (&MailScriptServiceServer{proxy: p}).ProcessMessage(context.Background(), &pb.ProcessRequest{From: "", To: []string{"user@example.com"}, RawMessage: []byte("From: a@example.com\r\nX-MailScript-Quarantine: forged\r\n\r\n.dot\r\n"), ForwardToUpstream: true})
	if err != nil || !resp.Accepted || !resp.Forwarded || resp.SmtpCode != 250 {
		t.Fatalf("%v, %v", resp, err)
	}
	transcript := <-messages
	for _, want := range []string{"MAIL FROM:<>\r\n", "X-MailScript-Quarantine: true\r\n", "\r\n..dot\r\n"} {
		if !strings.Contains(transcript, want) {
			t.Errorf("missing %q in %q", want, transcript)
		}
	}
	if strings.Contains(transcript, "forged") {
		t.Fatal("forged quarantine marker forwarded")
	}
}

func TestWireDataRejectsAmbiguousSMTPFraming(t *testing.T) {
	for _, raw := range []string{"Subject: x\n\nbody", "Subject: x\r\n\r\nbody\r.\rMAIL FROM:<x>", "Subject: x\r\n\r\nbody\r"} {
		if err := validateWireData([]byte(raw)); err == nil {
			t.Errorf("accepted ambiguous framing %q", raw)
		}
	}
	if err := validateWireData([]byte("Subject: x\r\n\r\n.dot\r\n")); err != nil {
		t.Fatal(err)
	}
}

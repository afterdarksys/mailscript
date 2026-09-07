package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

// upstreamTransaction stays open from MAIL through DATA. RCPT replies thus
// describe the same transaction that ultimately receives the filtered message.
type upstreamTransaction struct {
	conn       net.Conn
	reader     *bufio.Reader
	extensions map[string]string
}

type upstreamConfig struct {
	mode       string
	serverName string
	roots      *x509.CertPool
	username   string
	password   string
}

func loadUpstreamConfig(mode, name, ca, user string) (upstreamConfig, error) {
	c := upstreamConfig{mode: mode, serverName: name, username: user, password: os.Getenv("MAILSCRIPT_UPSTREAM_PASSWORD")}
	switch mode {
	case "plain", "starttls", "tls":
	default:
		return c, fmt.Errorf("--upstream-tls must be plain, starttls, or tls")
	}
	if user != "" && (mode == "plain" || c.password == "") {
		return c, fmt.Errorf("upstream authentication requires TLS and MAILSCRIPT_UPSTREAM_PASSWORD")
	}
	if ca != "" {
		pem, err := os.ReadFile(ca)
		if err != nil {
			return c, err
		}
		c.roots, err = x509.SystemCertPool()
		if err != nil {
			c.roots = x509.NewCertPool()
		}
		if !c.roots.AppendCertsFromPEM(pem) {
			return c, fmt.Errorf("no certificates in upstream CA file")
		}
	}
	return c, nil
}

func (u *upstreamTransaction) command(command string, want int) (int, string, error) {
	u.conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if command != "" {
		if _, err := fmt.Fprintf(u.conn, "%s\r\n", command); err != nil {
			return 0, "", err
		}
	}
	code, text, err := readSMTPReply(u.reader)
	if err != nil {
		return code, text, err
	}
	if want > 0 && code != want {
		return code, text, &upstreamError{code: code, stage: strings.SplitN(command, " ", 2)[0], text: text}
	}
	return code, text, nil
}

func (u *upstreamTransaction) hello() error {
	code, text, err := u.command("EHLO mailscript-proxy", 0)
	if err != nil {
		return err
	}
	u.extensions = map[string]string{}
	if code == 500 || code == 502 || code == 504 {
		_, _, err = u.command("HELO mailscript-proxy", 250)
		return err
	}
	if code != 250 {
		return &upstreamError{code: code, stage: "EHLO", text: text}
	}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if len(line) < 4 {
			continue
		}
		fields := strings.Fields(line[4:])
		if len(fields) > 0 {
			u.extensions[strings.ToUpper(fields[0])] = strings.Join(fields[1:], " ")
		}
	}
	return nil
}

func (s *SMTPSession) connectUpstream() (*upstreamTransaction, error) {
	host, _, err := net.SplitHostPort(s.proxy.upstreamServer)
	if err != nil {
		return nil, err
	}
	cfg := s.proxy.upstreamConfig
	if cfg.serverName != "" {
		host = cfg.serverName
	}
	tlsConfig := &tls.Config{ServerName: host, RootCAs: cfg.roots, MinVersion: tls.VersionTLS12}
	conn, err := net.DialTimeout("tcp", s.proxy.upstreamServer, 30*time.Second)
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			conn.Close()
		}
	}()
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if cfg.mode == "tls" {
		tc := tls.Client(conn, tlsConfig)
		if err := tc.Handshake(); err != nil {
			return nil, err
		}
		conn = tc
	}
	u := &upstreamTransaction{conn: conn, reader: bufio.NewReader(conn)}
	if _, _, err = u.command("", 220); err != nil {
		return nil, err
	}
	if err = u.hello(); err != nil {
		return nil, err
	}
	if cfg.mode == "starttls" {
		if _, ok := u.extensions["STARTTLS"]; !ok {
			return nil, fmt.Errorf("upstream does not advertise required STARTTLS")
		}
		if _, _, err = u.command("STARTTLS", 220); err != nil {
			return nil, err
		}
		tc := tls.Client(conn, tlsConfig)
		if err = tc.Handshake(); err != nil {
			return nil, err
		}
		conn = tc
		u.conn = tc
		u.reader = bufio.NewReader(tc)
		if err = u.hello(); err != nil {
			return nil, err
		}
	}
	user, password := cfg.username, cfg.password
	if s.authenticated {
		user, password = s.authUser, s.authPassword
	}
	if user != "" {
		if cfg.mode != "tls" && cfg.mode != "starttls" {
			return nil, fmt.Errorf("refusing plaintext upstream authentication")
		}
		plain := false
		for _, mechanism := range strings.Fields(u.extensions["AUTH"]) {
			if strings.EqualFold(mechanism, "PLAIN") {
				plain = true
			}
		}
		if !plain {
			return nil, fmt.Errorf("upstream does not support AUTH PLAIN")
		}
		payload := base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + password))
		if _, _, err = u.command("AUTH PLAIN "+payload, 235); err != nil {
			return nil, err
		}
	}
	success = true
	return u, nil
}

func (s *SMTPSession) beginUpstream() error {
	u, err := s.connectUpstream()
	if err != nil {
		return err
	}
	command := "MAIL FROM:<" + s.from + ">"
	if _, ok := u.extensions["8BITMIME"]; ok {
		command += " BODY=8BITMIME"
	}
	if _, _, err = u.command(command, 250); err != nil {
		u.conn.Close()
		return err
	}
	s.upstream = u
	return nil
}

func (s *SMTPSession) forwardToUpstream() error {
	if err := validateWireData(s.data); err != nil {
		return &upstreamError{code: 550, stage: "message", text: err.Error()}
	}
	if err := validateEnvelope(s.from, s.recipients); err != nil {
		return err
	}
	if s.upstream == nil {
		if err := s.beginUpstream(); err != nil {
			return err
		}
		// API calls have one outcome for all recipients. Do not partially deliver.
		accepted := 0
		var rejection *upstreamError
		for _, rcpt := range s.recipients {
			code, text, err := s.upstream.command("RCPT TO:<"+rcpt+">", 0)
			if err != nil {
				s.closeUpstream()
				return err
			}
			if code == 250 || code == 251 || code == 252 {
				accepted++
			} else if rejection == nil || rejection.code >= 500 || code < 500 {
				rejection = &upstreamError{code: code, stage: "RCPT TO", text: text}
			}
		}
		if rejection != nil {
			s.closeUpstream()
			if accepted > 0 {
				return &upstreamError{code: 451, stage: "RCPT TO", text: "Mixed recipient results; no message delivered"}
			}
			return rejection
		}
	}
	defer s.closeUpstream()
	u := s.upstream
	if _, _, err := u.command("DATA", 354); err != nil {
		return err
	}
	if _, err := u.conn.Write(dotStuff(s.data)); err != nil {
		return err
	}
	if !bytes.HasSuffix(s.data, []byte("\r\n")) {
		if _, err := fmt.Fprint(u.conn, "\r\n"); err != nil {
			return err
		}
	}
	_, _, err := u.command(".", 250)
	// Closing after 250 is sufficient; a failed QUIT cannot undo acceptance.
	return err
}

func (s *SMTPSession) closeUpstream() {
	if s.upstream != nil {
		s.upstream.conn.Close()
		s.upstream = nil
	}
}

func (s *SMTPSession) upstreamFailure(err error) {
	if ue, ok := err.(*upstreamError); ok && ue.code >= 400 && ue.code <= 599 {
		s.writeLine(ue.clientReply())
		if ue.code == 421 {
			s.conn.Close()
		}
	} else {
		s.writeLine("451 Upstream temporarily unavailable")
	}
}

func (s *SMTPSession) deliver(ctx context.Context) error {
	if s.proxy.hostAdapter != nil {
		s.closeUpstream()
		return s.proxy.hostAdapter.deliver(ctx, s)
	}
	var replacements, copies []string
	for _, action := range s.actions {
		parts := strings.SplitN(action, ":", 2)
		if len(parts) != 2 {
			continue
		}
		switch parts[0] {
		case "redirect", "divert_to":
			replacements = append(replacements, parts[1])
		case "screen_to":
			copies = append(copies, parts[1])
		}
	}
	if len(replacements) > 0 || len(copies) > 0 {
		recipients := append([]string(nil), s.recipients...)
		if len(replacements) > 0 {
			recipients = replacements
		}
		recipients = append(recipients, copies...)
		if err := validateEnvelope(s.from, recipients); err != nil {
			return err
		}
		seen := map[string]bool{}
		s.recipients = nil
		for _, recipient := range recipients {
			if !seen[recipient] {
				s.recipients = append(s.recipients, recipient)
				seen[recipient] = true
			}
		}
		s.closeUpstream()
	}
	return s.forwardToUpstream()
}

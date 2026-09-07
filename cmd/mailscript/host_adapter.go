package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Host delivery transfers the complete delivery plan in one operation. This
// lets a mailbox platform implement folder routing, replies, digests and DLP
// atomically without pretending that SMTP itself understands those operations.
type hostAdapter struct {
	base    string
	token   string
	client  *http.Client
	actions map[string]bool
}

type hostDeliveryRequest struct {
	Version  int      `json:"version"`
	ID       string   `json:"id"`
	From     string   `json:"from"`
	To       []string `json:"to"`
	Message  []byte   `json:"message"`
	Actions  []string `json:"actions"`
	ClientIP string   `json:"client_ip,omitempty"`
	HELO     string   `json:"helo,omitempty"`
}

type hostDeliveryResponse struct {
	ID       string `json:"id"`
	SMTPCode int    `json:"smtp_code"`
	Receipt  string `json:"receipt"`
	Reason   string `json:"reason"`
}

func newHostAdapter(base, token string) (*hostAdapter, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("invalid delivery adapter URL")
	}
	loopback := u.Hostname() == "localhost"
	if ip := net.ParseIP(u.Hostname()); ip != nil {
		loopback = ip.IsLoopback()
	}
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, fmt.Errorf("delivery adapter requires HTTPS or loopback HTTP")
	}
	a := &hostAdapter{base: strings.TrimRight(base, "/"), token: token, client: &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return fmt.Errorf("adapter redirect refused") }}, actions: map[string]bool{}}
	var capabilities struct {
		Version int      `json:"version"`
		Actions []string `json:"actions"`
	}
	if err := a.request(context.Background(), http.MethodGet, "/v1/capabilities", nil, &capabilities); err != nil {
		return nil, err
	}
	if capabilities.Version != 1 {
		return nil, fmt.Errorf("unsupported delivery adapter version")
	}
	for _, action := range capabilities.Actions {
		a.actions[action] = true
	}
	if !a.actions["accept"] {
		return nil, fmt.Errorf("delivery adapter must support accept")
	}
	return a, nil
}

func (a *hostAdapter) request(ctx context.Context, method, path string, body []byte, result any) error {
	req, err := http.NewRequestWithContext(ctx, method, a.base+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if a.token != "" {
		req.Header.Set("Authorization", "Bearer "+a.token)
	}
	resp, err := a.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024+1))
	if err != nil {
		return err
	}
	if len(raw) > 64*1024 {
		return fmt.Errorf("delivery adapter response too large")
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("delivery adapter HTTP %d", resp.StatusCode)
	}
	return json.Unmarshal(raw, result)
}

func (a *hostAdapter) deliver(ctx context.Context, s *SMTPSession) error {
	for _, action := range s.actions {
		name := strings.SplitN(action, ":", 2)[0]
		switch name {
		case "log", "add_header", "remove_header", "protect_metadata":
			continue
		}
		if !a.actions[name] {
			return fmt.Errorf("delivery adapter does not support action %s", name)
		}
	}
	request := hostDeliveryRequest{Version: 1, From: s.from, To: s.recipients, Message: s.data, Actions: s.actions, ClientIP: s.clientIP, HELO: s.helo}
	// The idempotency key deliberately excludes connection facts: retries can
	// arrive through a different hop. The message, envelope and plan identify
	// this delivery. The host must persist receipts and deduplicate this ID.
	identity, _ := json.Marshal(struct {
		From    string
		To      []string
		Message []byte
		Actions []string
	}{s.from, s.recipients, s.data, s.actions})
	sum := sha256.Sum256(identity)
	request.ID = hex.EncodeToString(sum[:])
	raw, err := json.Marshal(request)
	if err != nil {
		return err
	}
	var response hostDeliveryResponse
	if err = a.request(ctx, http.MethodPost, "/v1/deliver", raw, &response); err != nil {
		return err
	}
	if response.ID != request.ID {
		return fmt.Errorf("delivery adapter response ID mismatch")
	}
	if response.SMTPCode >= 400 && response.SMTPCode <= 599 {
		return &upstreamError{code: response.SMTPCode, stage: "host delivery", text: smtpReplyText(response.Reason)}
	}
	if response.SMTPCode != 250 || response.Receipt == "" {
		return fmt.Errorf("delivery adapter did not acknowledge durable delivery")
	}
	return nil
}

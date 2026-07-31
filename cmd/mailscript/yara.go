package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// yaraScanner talks only to a private scanner sidecar.  MailScript never
// executes tenant-supplied rules or a scanner binary in the SMTP process.
// The sidecar contract is POST /v1/scan with an RFC 822 message body and a
// JSON response containing `matches`, either as rule-name strings or objects
// with a `rule`, `name`, or `identifier` field.
type yaraScanner struct {
	endpoint string
	client   *http.Client
	maxBytes int64
}

func newYARAScanner(endpoint string, timeout time.Duration, maxBytes int64) *yaraScanner {
	return &yaraScanner{
		endpoint: strings.TrimRight(endpoint, "/"),
		client:   &http.Client{Timeout: timeout},
		maxBytes: maxBytes,
	}
}

func (s *yaraScanner) scan(ctx context.Context, message []byte) ([]string, error) {
	if s.maxBytes > 0 && int64(len(message)) > s.maxBytes {
		return nil, fmt.Errorf("message exceeds YARA scan limit of %d bytes", s.maxBytes)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/v1/scan", bytes.NewReader(message))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "message/rfc822")
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("YARA scanner returned %s", resp.Status)
	}
	var payload struct {
		Matches []json.RawMessage `json:"matches"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	matches := make([]string, 0, len(payload.Matches))
	seen := make(map[string]struct{}, len(payload.Matches))
	for _, raw := range payload.Matches {
		name, err := yaraMatchName(raw)
		if err != nil {
			return nil, err
		}
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		matches = append(matches, name)
	}
	return matches, nil
}

func yaraMatchName(raw json.RawMessage) (string, error) {
	var name string
	if err := json.Unmarshal(raw, &name); err == nil {
		return strings.TrimSpace(name), nil
	}
	var object struct {
		Rule       string `json:"rule"`
		Name       string `json:"name"`
		Identifier string `json:"identifier"`
	}
	if err := json.Unmarshal(raw, &object); err != nil {
		return "", fmt.Errorf("invalid YARA match: %w", err)
	}
	return strings.TrimSpace(firstNonEmpty(object.Rule, object.Name, object.Identifier)), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

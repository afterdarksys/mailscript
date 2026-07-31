package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/rules"
)

const maxAnalyzerResponseBytes = 1 << 20

// analyzerClient sends the original RFC 822 message to a private analysis
// sidecar. Native parsers and sandbox tooling stay outside the SMTP process.
type analyzerClient struct {
	name     string
	endpoint string
	client   *http.Client
	maxBytes int64
}

func newAnalyzerClient(name, endpoint string, timeout time.Duration, maxBytes int64) *analyzerClient {
	return &analyzerClient{
		name: name, endpoint: strings.TrimRight(endpoint, "/"),
		client: &http.Client{Timeout: timeout}, maxBytes: maxBytes,
	}
}

func (s *analyzerClient) analyze(ctx context.Context, message []byte) (rules.AnalyzerResult, error) {
	if s.maxBytes > 0 && int64(len(message)) > s.maxBytes {
		return rules.AnalyzerResult{}, fmt.Errorf("message exceeds analyzer limit of %d bytes", s.maxBytes)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.endpoint+"/v1/analyze", bytes.NewReader(message))
	if err != nil {
		return rules.AnalyzerResult{}, err
	}
	req.Header.Set("Content-Type", "message/rfc822")
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return rules.AnalyzerResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return rules.AnalyzerResult{}, fmt.Errorf("analyzer returned %s", resp.Status)
	}

	var result rules.AnalyzerResult
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxAnalyzerResponseBytes+1))
	if err := decoder.Decode(&result); err != nil {
		return rules.AnalyzerResult{}, err
	}
	result.Analyzer = s.name
	if err := normalizeAnalyzerResult(&result); err != nil {
		return rules.AnalyzerResult{}, err
	}
	return result, nil
}

func normalizeAnalyzerResult(result *rules.AnalyzerResult) error {
	result.Verdict = strings.ToLower(strings.TrimSpace(result.Verdict))
	switch result.Verdict {
	case "clean", "unknown", "suspicious", "malicious":
	default:
		return fmt.Errorf("invalid analyzer verdict %q", result.Verdict)
	}
	if result.Score < 0 || result.Score > 1 {
		return fmt.Errorf("analyzer score %.3f is outside 0..1", result.Score)
	}
	for i := range result.Findings {
		finding := &result.Findings[i]
		finding.Source = result.Analyzer
		finding.Code = strings.TrimSpace(finding.Code)
		finding.Summary = strings.TrimSpace(finding.Summary)
		if finding.Code == "" {
			return fmt.Errorf("analyzer finding %d has no code", i)
		}
		if finding.Confidence < 0 || finding.Confidence > 1 {
			return fmt.Errorf("analyzer finding %q confidence is outside 0..1", finding.Code)
		}
	}
	result.Categories = uniqueTrimmed(result.Categories)
	result.IOCs = uniqueTrimmed(result.IOCs)
	return nil
}

func uniqueTrimmed(values []string) []string {
	out := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	return out
}

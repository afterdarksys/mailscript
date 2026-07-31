package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAnalyzerClientPostsMessageAndNormalizesResult(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/analyze" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "message/rfc822" {
			t.Fatalf("Content-Type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"verdict":"SUSPICIOUS", "score":0.82,
			"categories":["execution","execution"],
			"findings":[{"code":" process/create-powershell ","summary":" Launches PowerShell ","confidence":0.91}]
		}`))
	}))
	defer server.Close()

	client := newAnalyzerClient("capa", server.URL, time.Second, 1024)
	result, err := client.analyze(context.Background(), []byte("Subject: test\r\n\r\nbody"))
	if err != nil {
		t.Fatal(err)
	}
	if result.Analyzer != "capa" || result.Verdict != "suspicious" || result.Score != 0.82 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if len(result.Categories) != 1 || len(result.Findings) != 1 {
		t.Fatalf("result was not normalized: %+v", result)
	}
	finding := result.Findings[0]
	if finding.Source != "capa" || finding.Code != "process/create-powershell" || finding.Summary != "Launches PowerShell" {
		t.Fatalf("unexpected finding: %+v", finding)
	}
}

func TestAnalyzerClientRejectsInvalidVerdictAndScore(t *testing.T) {
	for _, payload := range []string{
		`{"verdict":"possibly-bad","score":0.5}`,
		`{"verdict":"malicious","score":1.1}`,
	} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(payload))
		}))
		client := newAnalyzerClient("test", server.URL, time.Second, 1024)
		_, err := client.analyze(context.Background(), []byte("message"))
		server.Close()
		if err == nil {
			t.Fatalf("expected invalid payload %s to fail", payload)
		}
	}
}

func TestAnalyzerClientEnforcesMessageLimit(t *testing.T) {
	client := newAnalyzerClient("test", "http://127.0.0.1:1", time.Second, 3)
	if _, err := client.analyze(context.Background(), []byte("1234")); err == nil {
		t.Fatal("expected size-limit error")
	}
}

func TestAnalyzerConfigurationValidation(t *testing.T) {
	for _, name := range []string{"capa", "office-tools_1", "ocr.local"} {
		if !validAnalyzerName(name) {
			t.Fatalf("validAnalyzerName(%q) = false", name)
		}
	}
	for _, name := range []string{"", "bad name", "name/url"} {
		if validAnalyzerName(name) {
			t.Fatalf("validAnalyzerName(%q) = true", name)
		}
	}
	if !validAnalyzerEndpoint("http://127.0.0.1:4471") || validAnalyzerEndpoint("file:///tmp/analyzer") {
		t.Fatal("analyzer endpoint validation failed")
	}
}

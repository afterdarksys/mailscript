package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"
)

func TestYARAScannerPostsRFC822MessageAndNormalizesMatches(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/scan" {
			t.Fatalf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		if got := r.Header.Get("Content-Type"); got != "message/rfc822" {
			t.Fatalf("Content-Type = %q", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"matches":["suspicious_attachment",{"rule":"macro_dropper"},{"name":"macro_dropper"}]}`))
	}))
	defer server.Close()

	scanner := newYARAScanner(server.URL, time.Second, 1024)
	matches, err := scanner.scan(context.Background(), []byte("Subject: test\r\n\r\nbody"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"suspicious_attachment", "macro_dropper"}
	if !reflect.DeepEqual(matches, want) {
		t.Fatalf("matches = %#v, want %#v", matches, want)
	}
}

func TestYARAScannerEnforcesMessageLimit(t *testing.T) {
	scanner := newYARAScanner("http://127.0.0.1:1", time.Second, 3)
	if _, err := scanner.scan(context.Background(), []byte("1234")); err == nil {
		t.Fatal("expected size-limit error")
	}
}

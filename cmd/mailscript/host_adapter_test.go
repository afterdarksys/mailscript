package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHostAdapterCapabilitiesReceiptsAndRetryIdentity(t *testing.T) {
	var ids []string
	posts := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer secret" {
			t.Error("missing adapter authorization")
		}
		if r.URL.Path == "/v1/capabilities" {
			json.NewEncoder(w).Encode(map[string]any{"version": 1, "actions": []string{"accept", "fileinto", "auto_reply", "add_to_digest", "set_dlp"}})
			return
		}
		posts++
		var request hostDeliveryRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		ids = append(ids, request.ID)
		json.NewEncoder(w).Encode(hostDeliveryResponse{ID: request.ID, SMTPCode: 250, Receipt: "durable-job-1"})
	}))
	defer server.Close()
	adapter, err := newHostAdapter(server.URL, "secret")
	if err != nil {
		t.Fatal(err)
	}
	s := &SMTPSession{from: "sender@example.com", recipients: []string{"user@example.com"}, data: []byte("Subject: x\r\n\r\nbody"), actions: []string{"fileinto:Inbox", "auto_reply:away", "set_dlp:enforce:all", "add_to_digest"}}
	if err := adapter.deliver(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	s.clientIP = "192.0.2.2"
	if err := adapter.deliver(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	if ids[0] != ids[1] {
		t.Fatal("retry received a different ID")
	}
	s.actions = []string{"force_second_pass:other"}
	if err := adapter.deliver(context.Background(), s); err == nil {
		t.Fatal("unsupported action ignored")
	}
	if posts != 2 {
		t.Fatal("unsupported plan was submitted")
	}
}

func TestHostAdapterDoesNotAcceptMissingReceipt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/capabilities" {
			json.NewEncoder(w).Encode(map[string]any{"version": 1, "actions": []string{"accept"}})
			return
		}
		var request hostDeliveryRequest
		json.NewDecoder(r.Body).Decode(&request)
		json.NewEncoder(w).Encode(hostDeliveryResponse{ID: request.ID, SMTPCode: 250})
	}))
	defer server.Close()
	adapter, err := newHostAdapter(server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := adapter.deliver(context.Background(), &SMTPSession{actions: []string{"accept"}}); err == nil {
		t.Fatal("uncommitted delivery accepted")
	}
}

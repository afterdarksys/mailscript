package main

import (
	"context"
	"strings"
	"testing"
	"time"

	mailscriptpb "github.com/afterdarksys/mailscript/pkg/proto"
)

func TestGRPCServiceProcessesMessage(t *testing.T) {
	proxy := &SMTPProxy{script: "def evaluate():\n    accept()\n", scriptName: "test.star", stats: &ProxyStats{StartTime: time.Now()}}
	service := &MailScriptServiceServer{proxy: proxy}
	response, err := service.ProcessMessage(context.Background(), &mailscriptpb.ProcessRequest{
		From: "sender@example.com", To: []string{"recipient@example.net"},
		Headers: map[string]string{"From": "sender@example.com", "Subject": "test"}, Body: "hello",
	})
	if err != nil || !response.Accepted {
		t.Fatalf("unexpected response: response=%+v err=%v", response, err)
	}
}

func TestGRPCMessageRejectsHeaderInjection(t *testing.T) {
	_, err := grpcMessage(&mailscriptpb.ProcessRequest{Headers: map[string]string{"Subject": "safe\r\nBcc: victim@example.net"}})
	if err == nil || !strings.Contains(err.Error(), "prohibited") {
		t.Fatalf("expected header injection error, got %v", err)
	}
}

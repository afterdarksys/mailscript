package main

import (
	"context"
	"strings"
	"testing"
	"time"

	mailscriptpb "github.com/afterdarksys/mailscript/pkg/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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

// Threats: the SMTP proxy path (processWithMailScript, proxy.go) strips
// X-MailScript-Quarantine before parsing precisely because it's a private
// proxy-to-upstream control signal — a client that could set it and have it
// honored could route its own mail wherever it wants post-quarantine, or
// suppress quarantine handling entirely. The gRPC path takes the same kind
// of untrusted caller-supplied headers and must apply the identical strip.
func TestGRPCProcessMessageStripsClientSuppliedQuarantineHeader(t *testing.T) {
	proxy := &SMTPProxy{
		script:     "def evaluate():\n    if has_header(\"X-MailScript-Quarantine\"):\n        reject(\"quarantine header was not stripped\")\n    accept()\n",
		scriptName: "test.star",
		stats:      &ProxyStats{StartTime: time.Now()},
	}
	service := &MailScriptServiceServer{proxy: proxy}
	response, err := service.ProcessMessage(context.Background(), &mailscriptpb.ProcessRequest{
		From: "sender@example.com", To: []string{"recipient@example.net"},
		Headers: map[string]string{"From": "sender@example.com", "X-MailScript-Quarantine": "true"},
		Body:    "hello",
	})
	if err != nil {
		t.Fatalf("ProcessMessage() error = %v", err)
	}
	if !response.Accepted {
		t.Fatalf("client-supplied X-MailScript-Quarantine was not stripped: %+v", response)
	}
}

// Threats: if runtime.apply has no AV scanner configured, it never touches
// VirusStatus — whatever ProcessMessage sets before calling it is final.
// Hardcoding "clean" would make every virus_status()-gated policy silently
// pass mail submitted over gRPC when no scanner is even running.
func TestGRPCProcessMessageDefaultsVirusStatusToUnknown(t *testing.T) {
	proxy := &SMTPProxy{
		script:     "def evaluate():\n    if getvirusstatus() != \"unknown\":\n        reject(\"expected unknown with no AV configured, got \" + getvirusstatus())\n    accept()\n",
		scriptName: "test.star",
		stats:      &ProxyStats{StartTime: time.Now()},
	}
	service := &MailScriptServiceServer{proxy: proxy}
	response, err := service.ProcessMessage(context.Background(), &mailscriptpb.ProcessRequest{
		From: "sender@example.com", To: []string{"recipient@example.net"},
		Headers: map[string]string{"From": "sender@example.com"}, Body: "hello",
	})
	if err != nil {
		t.Fatalf("ProcessMessage() error = %v", err)
	}
	if !response.Accepted {
		t.Fatalf("VirusStatus was not the safe \"unknown\" default with no scanner configured: %+v", response)
	}
}

func TestIsLoopbackAddr(t *testing.T) {
	loopback := []string{"127.0.0.1", "::1", "localhost"}
	for _, addr := range loopback {
		if !isLoopbackAddr(addr) {
			t.Errorf("isLoopbackAddr(%q) = false, want true", addr)
		}
	}
	nonLoopback := []string{"0.0.0.0", "10.0.0.5", "203.0.113.7", ""}
	for _, addr := range nonLoopback {
		if isLoopbackAddr(addr) {
			t.Errorf("isLoopbackAddr(%q) = true, want false", addr)
		}
	}
}

// Threats: this is the property that prevents the server from silently
// listening unauthenticated on every interface — see startGRPCServer's doc
// comment. A non-loopback bind with no token must never succeed.
func TestStartGRPCServerFailsClosedOnNonLoopbackWithoutToken(t *testing.T) {
	proxy := &SMTPProxy{script: "def evaluate():\n    accept()\n", scriptName: "test.star", stats: &ProxyStats{StartTime: time.Now()}}
	err := proxy.startGRPCServer("0.0.0.0", 0, "")
	if err == nil {
		t.Fatal("startGRPCServer on 0.0.0.0 with no auth token = nil error, want a fail-closed refusal")
	}
}

func TestGRPCTokenAuthRejectsMissingMetadata(t *testing.T) {
	auth := &grpcTokenAuth{token: "correct-token"}
	err := auth.authorize(context.Background())
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("authorize() with no metadata = %v, want Unauthenticated", err)
	}
}

func TestGRPCTokenAuthRejectsWrongToken(t *testing.T) {
	auth := &grpcTokenAuth{token: "correct-token"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer wrong-token"))
	err := auth.authorize(ctx)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("authorize() with the wrong token = %v, want Unauthenticated", err)
	}
}

func TestGRPCTokenAuthRejectsMissingBearerPrefix(t *testing.T) {
	auth := &grpcTokenAuth{token: "correct-token"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "correct-token"))
	err := auth.authorize(ctx)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("authorize() without the Bearer scheme = %v, want Unauthenticated", err)
	}
}

func TestGRPCTokenAuthAcceptsCorrectToken(t *testing.T) {
	auth := &grpcTokenAuth{token: "correct-token"}
	ctx := metadata.NewIncomingContext(context.Background(), metadata.Pairs("authorization", "Bearer correct-token"))
	if err := auth.authorize(ctx); err != nil {
		t.Fatalf("authorize() with the correct token = %v, want nil", err)
	}
}

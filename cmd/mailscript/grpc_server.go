package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"google.golang.org/grpc"
)

// gRPC service implementation
type MailScriptServiceServer struct {
	proxy *SMTPProxy
}

// ProcessMessage processes a single message through MailScript
func (s *MailScriptServiceServer) ProcessMessage(ctx context.Context, req *ProcessRequest) (*ProcessResponse, error) {
	startTime := time.Now()

	// Build message context
	msgCtx := &rules.MessageContext{
		Headers:         req.Headers,
		Body:            req.Body,
		MimeType:        req.Headers["Content-Type"],
		SpamScore:       0.0,
		VirusStatus:     "clean",
		Actions:         []string{},
		LogEntries:      []string{},
		ModifiedHeaders: make(map[string]string),
		SenderDomain:    extractDomain(req.From),
		DNSResolved:     true,
		RBLListed:       false,
	}

	// Execute MailScript
	if err := rules.ExecuteEngine(s.proxy.script, msgCtx); err != nil {
		return &ProcessResponse{
			Accepted:         false,
			Reason:           fmt.Sprintf("Script error: %v", err),
			ProcessingTimeMs: time.Since(startTime).Milliseconds(),
		}, nil
	}

	// Check actions for rejection
	accepted := true
	reason := "Message accepted"

	for _, action := range msgCtx.Actions {
		switch {
		case action == "discard":
			accepted = false
			reason = "Message discarded by filter"
		case action == "quarantine":
			accepted = false
			reason = "Message quarantined"
		case strings.HasPrefix(action, "fileinto:Spam"):
			accepted = false
			reason = "Classified as spam"
		case action == "bounce":
			accepted = false
			reason = "Message bounced"
		case action == "drop":
			accepted = false
			reason = "Message dropped"
		}
	}

	// Update stats
	s.proxy.stats.Lock()
	s.proxy.stats.MessagesProcessed++
	if accepted {
		s.proxy.stats.MessagesAccepted++
	} else {
		s.proxy.stats.MessagesRejected++
	}
	s.proxy.stats.Unlock()

	// Forward to upstream if requested and accepted
	if accepted && req.ForwardToUpstream && s.proxy.upstreamServer != "" {
		if err := s.forwardViaGRPC(req); err != nil {
			return &ProcessResponse{
				Accepted:         false,
				Reason:           fmt.Sprintf("Upstream forward failed: %v", err),
				Actions:          msgCtx.Actions,
				Logs:             msgCtx.LogEntries,
				ModifiedHeaders:  msgCtx.ModifiedHeaders,
				ProcessingTimeMs: time.Since(startTime).Milliseconds(),
			}, nil
		}
	}

	return &ProcessResponse{
		Accepted:         accepted,
		Reason:           reason,
		Actions:          msgCtx.Actions,
		Logs:             msgCtx.LogEntries,
		ModifiedHeaders:  msgCtx.ModifiedHeaders,
		ProcessingTimeMs: time.Since(startTime).Milliseconds(),
	}, nil
}

// ProcessMessageStream handles streaming message processing
func (s *MailScriptServiceServer) ProcessMessageStream(stream MailScriptService_ProcessMessageStreamServer) error {
	for {
		req, err := stream.Recv()
		if err != nil {
			return err
		}

		resp, err := s.ProcessMessage(stream.Context(), req)
		if err != nil {
			return err
		}

		if err := stream.Send(resp); err != nil {
			return err
		}
	}
}

// GetStats returns proxy statistics
func (s *MailScriptServiceServer) GetStats(ctx context.Context, req *StatsRequest) (*StatsResponse, error) {
	s.proxy.stats.Lock()
	defer s.proxy.stats.Unlock()

	return &StatsResponse{
		TotalConnections:  s.proxy.stats.TotalConnections,
		ActiveConnections: s.proxy.stats.ActiveConnections,
		MessagesProcessed: s.proxy.stats.MessagesProcessed,
		MessagesAccepted:  s.proxy.stats.MessagesAccepted,
		MessagesRejected:  s.proxy.stats.MessagesRejected,
		BytesProcessed:    s.proxy.stats.BytesProcessed,
		UptimeSeconds:     int64(time.Since(s.proxy.stats.StartTime).Seconds()),
	}, nil
}

// Health check
func (s *MailScriptServiceServer) Health(ctx context.Context, req *HealthRequest) (*HealthResponse, error) {
	return &HealthResponse{
		Healthy:    true,
		Version:    "1.0.0",
		ScriptPath: scriptPath,
	}, nil
}

func (s *MailScriptServiceServer) forwardViaGRPC(req *ProcessRequest) error {
	// Connect to upstream SMTP and forward
	conn, err := net.DialTimeout("tcp", s.proxy.upstreamServer, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to upstream: %w", err)
	}
	defer conn.Close()

	// Build SMTP message from gRPC request
	var message strings.Builder

	// Headers
	for key, value := range req.Headers {
		message.WriteString(fmt.Sprintf("%s: %s\r\n", key, value))
	}
	message.WriteString("\r\n")

	// Body
	message.WriteString(req.Body)

	// TODO: Actually send via SMTP protocol
	log.Printf("Would forward message to %s", s.proxy.upstreamServer)
	return nil
}

func (p *SMTPProxy) startGRPCServer(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to start gRPC listener: %w", err)
	}

	_ = grpc.NewServer()

	// Register service - NOTE: This requires generating the proto code
	// For now, this is a placeholder showing the structure
	log.Printf("🔌 gRPC server placeholder on port %d", port)
	log.Printf("⚠️  Note: Run 'protoc' to generate gRPC bindings from mailscript.proto")
	log.Printf("📝 Proto file: pkg/proto/mailscript.proto")

	// TODO: Uncomment after generating proto code
	// RegisterMailScriptServiceServer(grpcServer, &MailScriptServiceServer{proxy: p})
	// if err := grpcServer.Serve(listener); err != nil {
	// 	return fmt.Errorf("gRPC server error: %w", err)
	// }

	// For now, keep listener open but don't serve
	defer listener.Close()
	select {} // Block forever
}

// Placeholder types until proto is generated
type ProcessRequest struct {
	From              string
	To                []string
	Headers           map[string]string
	Body              string
	ForwardToUpstream bool
}

type ProcessResponse struct {
	Accepted         bool
	Reason           string
	Actions          []string
	Logs             []string
	ModifiedHeaders  map[string]string
	ProcessingTimeMs int64
}

type StatsRequest struct{}

type StatsResponse struct {
	TotalConnections  int64
	ActiveConnections int64
	MessagesProcessed int64
	MessagesAccepted  int64
	MessagesRejected  int64
	BytesProcessed    int64
	UptimeSeconds     int64
}

type HealthRequest struct{}

type HealthResponse struct {
	Healthy    bool
	Version    string
	ScriptPath string
}

type MailScriptService_ProcessMessageStreamServer interface {
	Recv() (*ProcessRequest, error)
	Send(*ProcessResponse) error
	Context() context.Context
}

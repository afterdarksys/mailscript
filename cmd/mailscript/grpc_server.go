package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	mailscriptpb "github.com/afterdarksys/mailscript/pkg/proto"
	"github.com/afterdarksys/mailscript/pkg/rules"
	"google.golang.org/grpc"
)

type MailScriptServiceServer struct {
	mailscriptpb.UnimplementedMailScriptServiceServer
	proxy *SMTPProxy
}

func (s *MailScriptServiceServer) ProcessMessage(_ context.Context, req *mailscriptpb.ProcessRequest) (*mailscriptpb.ProcessResponse, error) {
	start := time.Now()
	raw, err := grpcMessage(req)
	if err != nil {
		return &mailscriptpb.ProcessResponse{Accepted: false, Reason: "Invalid message headers: " + err.Error(), ProcessingTimeMs: time.Since(start).Milliseconds()}, nil
	}
	msgCtx, err := rules.ParseMessage(raw)
	if err != nil {
		return &mailscriptpb.ProcessResponse{Accepted: false, Reason: "Invalid RFC 822 message: " + err.Error(), ProcessingTimeMs: time.Since(start).Milliseconds()}, nil
	}
	msgCtx.VirusStatus = "clean"
	msgCtx.SenderDomain = extractDomain(req.From)
	msgCtx.EnvelopeFrom = req.From
	msgCtx.EnvelopeTo = append([]string(nil), req.To...)
	msgCtx.DNSResolved = true
	if s.proxy.runtime != nil {
		s.proxy.runtime.apply(msgCtx)
	}
	if err := rules.ExecuteEngineWithOptions(s.proxy.script, msgCtx, s.proxy.engineOptions()); err != nil {
		return &mailscriptpb.ProcessResponse{Accepted: false, Reason: "Script error: " + err.Error(), ProcessingTimeMs: time.Since(start).Milliseconds()}, nil
	}

	accepted, reason := grpcDisposition(msgCtx.Actions)
	if accepted && req.ForwardToUpstream {
		if s.proxy.upstreamServer == "" {
			accepted, reason = false, "Upstream forwarding requested but no upstream is configured"
		} else {
			raw = applyHeaderChanges(raw, msgCtx.RemovedHeaders, msgCtx.ModifiedHeaders)
			session := &SMTPSession{proxy: s.proxy, from: req.From, recipients: append([]string(nil), req.To...), data: raw}
			if session.from == "" || len(session.recipients) == 0 {
				accepted, reason = false, "Upstream forwarding requires an envelope sender and recipient"
			} else if err := session.forwardToUpstream(); err != nil {
				accepted, reason = false, "Upstream forward failed: "+err.Error()
			}
		}
	}

	s.proxy.stats.Lock()
	s.proxy.stats.MessagesProcessed++
	if accepted {
		s.proxy.stats.MessagesAccepted++
	} else {
		s.proxy.stats.MessagesRejected++
	}
	s.proxy.stats.Unlock()

	return &mailscriptpb.ProcessResponse{
		Accepted: accepted, Reason: reason, Actions: msgCtx.Actions, Logs: msgCtx.LogEntries,
		ModifiedHeaders: msgCtx.ModifiedHeaders, ProcessingTimeMs: time.Since(start).Milliseconds(),
	}, nil
}

func grpcDisposition(actions []string) (bool, string) {
	for _, action := range actions {
		switch {
		case action == "discard", action == "drop", action == "bounce":
			return false, "Message rejected by " + action + " action"
		case action == "quarantine", strings.HasPrefix(action, "fileinto:Spam"):
			return false, "Message quarantined by policy"
		}
	}
	return true, "Message accepted"
}

func grpcMessage(req *mailscriptpb.ProcessRequest) ([]byte, error) {
	var message strings.Builder
	// Map iteration is randomized; stable ordering makes forwarding tests and
	// DKIM behavior deterministic for API-created messages.
	names := make([]string, 0, len(req.Headers))
	for name := range req.Headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if name == "" || strings.ContainsAny(name, "\r\n:\x00") || strings.ContainsAny(req.Headers[name], "\r\n\x00") {
			return nil, fmt.Errorf("header %q contains prohibited characters", name)
		}
		message.WriteString(name + ": " + req.Headers[name] + "\r\n")
	}
	message.WriteString("\r\n")
	message.WriteString(req.Body)
	return []byte(message.String()), nil
}

func (s *MailScriptServiceServer) ProcessMessageStream(stream mailscriptpb.MailScriptService_ProcessMessageStreamServer) error {
	for {
		req, err := stream.Recv()
		if err == io.EOF {
			return nil
		}
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

func (s *MailScriptServiceServer) GetStats(context.Context, *mailscriptpb.StatsRequest) (*mailscriptpb.StatsResponse, error) {
	s.proxy.stats.Lock()
	defer s.proxy.stats.Unlock()
	return &mailscriptpb.StatsResponse{
		TotalConnections: s.proxy.stats.TotalConnections, ActiveConnections: s.proxy.stats.ActiveConnections,
		MessagesProcessed: s.proxy.stats.MessagesProcessed, MessagesAccepted: s.proxy.stats.MessagesAccepted,
		MessagesRejected: s.proxy.stats.MessagesRejected, BytesProcessed: s.proxy.stats.BytesProcessed,
		UptimeSeconds: int64(time.Since(s.proxy.stats.StartTime).Seconds()),
	}, nil
}

func (s *MailScriptServiceServer) Health(context.Context, *mailscriptpb.HealthRequest) (*mailscriptpb.HealthResponse, error) {
	return &mailscriptpb.HealthResponse{Healthy: true, Version: "1.0.0", ScriptPath: s.proxy.scriptName}, nil
}

func (p *SMTPProxy) startGRPCServer(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to start gRPC listener: %w", err)
	}
	server := grpc.NewServer()
	mailscriptpb.RegisterMailScriptServiceServer(server, &MailScriptServiceServer{proxy: p})
	return server.Serve(listener)
}

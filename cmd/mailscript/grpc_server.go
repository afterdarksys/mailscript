package main

import (
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	mailscriptpb "github.com/afterdarksys/mailscript/pkg/proto"
	"github.com/afterdarksys/mailscript/pkg/rules"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
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
	// This header is a private proxy-to-upstream control signal — see the
	// identical strip in processWithMailScript (proxy.go). A gRPC caller must
	// not be able to set it and have the message routed as pre-quarantined.
	raw = stripHeader(raw, "X-MailScript-Quarantine")
	msgCtx, err := rules.ParseMessage(raw)
	if err != nil {
		return &mailscriptpb.ProcessResponse{Accepted: false, Reason: "Invalid RFC 822 message: " + err.Error(), ProcessingTimeMs: time.Since(start).Milliseconds()}, nil
	}
	// Matches processWithMailScript's default (proxy.go): "unknown", not
	// "clean". If runtime.apply below has no scanner configured, this value
	// is never overwritten — hardcoding "clean" would let any virus_status()
	// policy check silently pass every message with no AV running at all.
	msgCtx.VirusStatus = "unknown"
	msgCtx.SenderDomain = extractDomain(req.From)
	msgCtx.EnvelopeFrom = req.From
	msgCtx.EnvelopeTo = append([]string(nil), req.To...)
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

// isLoopbackAddr reports whether addr is a loopback host — the only case in
// which an unauthenticated gRPC listener is acceptable, since reaching it
// then requires local access to the host already.
func isLoopbackAddr(addr string) bool {
	switch addr {
	case "127.0.0.1", "::1", "localhost":
		return true
	}
	ip := net.ParseIP(addr)
	return ip != nil && ip.IsLoopback()
}

// startGRPCServer starts the gRPC listener on listenAddr:port. Threats: this
// service can trigger real SMTP delivery to the upstream server
// (ProcessMessage with ForwardToUpstream) and evaluates arbitrary policy
// scripts against attacker-supplied message content, so an unauthenticated,
// non-loopback listener is an open relay/injection point into the mail
// system it fronts. Fails closed: refuses to start rather than falling back
// to an unauthenticated listener when authToken is empty and listenAddr
// isn't loopback-only.
func (p *SMTPProxy) startGRPCServer(listenAddr string, port int, authToken string) error {
	if authToken == "" && !isLoopbackAddr(listenAddr) {
		return fmt.Errorf("refusing to start gRPC server on %s:%d: no auth token configured (--grpc-auth-token or MAILSCRIPT_GRPC_TOKEN) and the address is not loopback-only", listenAddr, port)
	}

	listener, err := net.Listen("tcp", fmt.Sprintf("%s:%d", listenAddr, port))
	if err != nil {
		return fmt.Errorf("failed to start gRPC listener: %w", err)
	}

	var opts []grpc.ServerOption
	if authToken != "" {
		auth := &grpcTokenAuth{token: authToken}
		opts = append(opts, grpc.UnaryInterceptor(auth.unaryInterceptor), grpc.StreamInterceptor(auth.streamInterceptor))
	}

	server := grpc.NewServer(opts...)
	mailscriptpb.RegisterMailScriptServiceServer(server, &MailScriptServiceServer{proxy: p})
	return server.Serve(listener)
}

// grpcTokenAuth enforces a bearer token on every RPC via gRPC metadata:
// "authorization: Bearer <token>". Comparison is constant-time to avoid
// leaking the token through response-timing side channels.
type grpcTokenAuth struct {
	token string
}

func (a *grpcTokenAuth) authorize(ctx context.Context) error {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return status.Error(codes.Unauthenticated, "missing authorization metadata")
	}
	values := md.Get("authorization")
	if len(values) == 0 {
		return status.Error(codes.Unauthenticated, "missing authorization header")
	}
	const prefix = "Bearer "
	presented := values[0]
	if !strings.HasPrefix(presented, prefix) {
		return status.Error(codes.Unauthenticated, "authorization header must use the Bearer scheme")
	}
	presented = strings.TrimPrefix(presented, prefix)
	if subtle.ConstantTimeCompare([]byte(presented), []byte(a.token)) != 1 {
		return status.Error(codes.Unauthenticated, "invalid token")
	}
	return nil
}

func (a *grpcTokenAuth) unaryInterceptor(ctx context.Context, req interface{}, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (interface{}, error) {
	if err := a.authorize(ctx); err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

func (a *grpcTokenAuth) streamInterceptor(srv interface{}, ss grpc.ServerStream, _ *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
	if err := a.authorize(ss.Context()); err != nil {
		return err
	}
	return handler(srv, ss)
}

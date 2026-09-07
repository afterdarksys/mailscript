package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var proxyCmd = &cobra.Command{
	Use:   "proxy",
	Short: "Run MailScript as an SMTP proxy/gateway",
	Long: `Run MailScript as a full SMTP proxy server with gRPC interface.

This creates a filtering gateway that sits in front of your mail server,
applying MailScript rules to messages in real-time as they flow through.

The cheeky port numbers (3025, 3587) reference standard SMTP ports (25, 587)
but are prefixed with "3" to avoid conflicts and root requirements.

Features:
  - SMTP proxy on configurable ports (default: 3025, 3587)
  - Apply MailScript filtering rules to all messages
  - gRPC interface for non-mail app integration
  - TLS/STARTTLS support
  - Real-time message processing
  - Upstream server forwarding

The gRPC interface can trigger real SMTP delivery through --upstream and
evaluates your policy script against caller-supplied message content, so it
binds to 127.0.0.1 by default and refuses to start on any other address
without an auth token (--grpc-auth-token or MAILSCRIPT_GRPC_TOKEN) — there is
no unauthenticated non-loopback mode.

Examples:
  # Run SMTP proxy on ports 3025 and 3587
  mailscript proxy --script=filter.star --upstream=127.0.0.1:2525 --port=3025,3587

  # Enable TLS
  mailscript proxy --script=filter.star --upstream=127.0.0.1:2525 --enable-tls --cert=cert.pem --key=key.pem

  # Disable TLS
  mailscript proxy --script=filter.star --upstream=127.0.0.1:2525 --disable-tls

  # Forward to upstream server
  mailscript proxy --script=filter.star --upstream=mail.example.com:25

  # Expose gRPC beyond localhost (requires a token)
  mailscript proxy --script=filter.star --upstream=127.0.0.1:2525 --grpc-listen=0.0.0.0 --grpc-auth-token=$(openssl rand -hex 32)
`,
	RunE: runProxy,
}

var (
	proxyPorts                                                 []int
	enableTLS                                                  bool
	disableTLS                                                 bool
	certFile                                                   string
	keyFile                                                    string
	upstreamServer                                             string
	grpcPort                                                   int
	grpcListenAddr                                             string
	grpcAuthToken                                              string
	maxConnections                                             int
	smtpListenAddr                                             string
	forwardQuarantine                                          bool
	upstreamTLSMode, upstreamTLSName, upstreamCA, upstreamUser string
	submission                                                 bool
)

var deliveryAdapterURL string

func init() {
	rootCmd.AddCommand(proxyCmd)

	proxyCmd.Flags().StringVar(&scriptPath, "script", "", "Path to MailScript file (required)")
	proxyCmd.Flags().IntSliceVar(&proxyPorts, "port", []int{3025, 3587}, "SMTP ports to listen on (comma-separated)")
	proxyCmd.Flags().BoolVar(&enableTLS, "enable-tls", false, "Enable TLS/STARTTLS")
	proxyCmd.Flags().BoolVar(&disableTLS, "disable-tls", false, "Disable TLS (plaintext only)")
	proxyCmd.Flags().StringVar(&certFile, "cert", "", "TLS certificate file")
	proxyCmd.Flags().StringVar(&keyFile, "key", "", "TLS key file")
	proxyCmd.Flags().StringVar(&upstreamServer, "upstream", "", "Upstream SMTP server (e.g., mail.example.com:25)")
	proxyCmd.Flags().IntVar(&grpcPort, "grpc-port", 50051, "gRPC port for programmatic access")
	proxyCmd.Flags().StringVar(&grpcListenAddr, "grpc-listen", "127.0.0.1", "gRPC bind address. Non-loopback addresses require --grpc-auth-token (or MAILSCRIPT_GRPC_TOKEN) — the server refuses to start otherwise")
	proxyCmd.Flags().StringVar(&grpcAuthToken, "grpc-auth-token", "", "Bearer token required on every gRPC call. Falls back to the MAILSCRIPT_GRPC_TOKEN environment variable if unset")
	proxyCmd.Flags().StringVar(&smtpListenAddr, "listen", "127.0.0.1", "SMTP bind address")
	proxyCmd.Flags().IntVar(&maxConnections, "max-connections", 100, "Maximum concurrent connections")
	proxyCmd.Flags().BoolVar(&forwardQuarantine, "forward-quarantine", false, "Relay quarantined mail upstream with a trusted X-MailScript-Quarantine marker")

	proxyCmd.Flags().StringVar(&upstreamTLSMode, "upstream-tls", "plain", "Backend transport: plain, starttls (required), or tls (implicit)")
	proxyCmd.Flags().StringVar(&upstreamTLSName, "upstream-tls-name", "", "Backend TLS certificate hostname (default upstream hostname)")
	proxyCmd.Flags().StringVar(&upstreamCA, "upstream-ca", "", "Additional PEM root certificates for backend TLS")
	proxyCmd.Flags().StringVar(&upstreamUser, "upstream-user", "", "Backend service account; password from MAILSCRIPT_UPSTREAM_PASSWORD")
	proxyCmd.Flags().BoolVar(&submission, "submission", false, "Require incoming TLS and AUTH PLAIN verified by the backend")
	proxyCmd.Flags().StringVar(&deliveryAdapterURL, "delivery-adapter", "", "Host delivery API URL; token from MAILSCRIPT_DELIVERY_TOKEN")
	addRuntimeFlags(proxyCmd)

	proxyCmd.MarkFlagRequired("script")
}

func runProxy(cmd *cobra.Command, args []string) error {
	if upstreamServer == "" {
		return fmt.Errorf("--upstream is required: the proxy has no local delivery queue")
	}
	if _, _, err := net.SplitHostPort(upstreamServer); err != nil {
		return fmt.Errorf("invalid --upstream: %w", err)
	}
	if maxConnections <= 0 {
		return fmt.Errorf("--max-connections must be positive")
	}
	token := grpcAuthToken
	if token == "" {
		token = os.Getenv("MAILSCRIPT_GRPC_TOKEN")
	}
	if token == "" && !isLoopbackAddr(grpcListenAddr) {
		return fmt.Errorf("non-loopback gRPC requires an auth token")
	}
	upCfg, err := loadUpstreamConfig(upstreamTLSMode, upstreamTLSName, upstreamCA, upstreamUser)
	if err != nil {
		return err
	}
	if submission && (!enableTLS || disableTLS || upstreamTLSMode == "plain") {
		return fmt.Errorf("--submission requires incoming TLS and encrypted upstream transport")
	}
	// Read script
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read script: %w", err)
	}

	rt, err := buildRuntime()
	if err != nil {
		return err
	}

	proxy := &SMTPProxy{
		upstreamConfig:    upCfg,
		submission:        submission,
		listenAddr:        smtpListenAddr,
		script:            string(scriptContent),
		scriptName:        scriptPath,
		runtime:           rt,
		upstreamServer:    upstreamServer,
		maxConnections:    maxConnections,
		forwardQuarantine: forwardQuarantine,
		connections:       make(map[string]time.Time),
		stats: &ProxyStats{
			StartTime: time.Now(),
		},
	}

	if err := proxy.reloadPolicy(); err != nil {
		return fmt.Errorf("invalid policy: %w", err)
	}
	if deliveryAdapterURL != "" {
		proxy.hostAdapter, err = newHostAdapter(deliveryAdapterURL, os.Getenv("MAILSCRIPT_DELIVERY_TOKEN"))
		if err != nil {
			return fmt.Errorf("delivery adapter: %w", err)
		}
	}
	// Load TLS config if enabled
	if enableTLS && !disableTLS {
		if certFile == "" || keyFile == "" {
			return fmt.Errorf("--cert and --key required when --enable-tls is set")
		}

		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return fmt.Errorf("failed to load TLS certificate: %w", err)
		}

		proxy.tlsConfig = &tls.Config{
			Certificates: []tls.Certificate{cert},
			MinVersion:   tls.VersionTLS12,
		}
		fmt.Println("TLS enabled")
	} else if disableTLS {
		fmt.Println("WARNING: TLS disabled, running in plaintext mode")
	}

	// Bind every endpoint before reporting readiness.
	server, grpcListener, err := proxy.newGRPCServer(grpcListenAddr, grpcPort, token)
	if err != nil {
		return err
	}
	defer grpcListener.Close()
	defer server.Stop()
	listeners := make([]net.Listener, 0, len(proxyPorts))
	defer func() {
		for _, listener := range listeners {
			listener.Close()
		}
	}()
	for _, port := range proxyPorts {
		listener, err := net.Listen("tcp", net.JoinHostPort(smtpListenAddr, strconv.Itoa(port)))
		if err != nil {
			return err
		}
		listeners = append(listeners, listener)
	}
	failures := make(chan error, len(listeners)+1)
	go func() { failures <- server.Serve(grpcListener) }()
	for _, listener := range listeners {
		go func(l net.Listener) { failures <- proxy.serveSMTP(l) }(listener)
	}
	log.Printf("MailScript ready: SMTP %s:%v, upstream %s", smtpListenAddr, proxyPorts, upstreamServer)
	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	defer proxy.drain(listeners, server, 30*time.Second)
	for {
		select {
		case err := <-failures:
			return err
		case <-ctx.Done():
			return nil
		case <-reload:
			if err := proxy.reloadPolicy(); err != nil {
				log.Printf("Policy reload rejected; retaining previous snapshot: %v", err)
			} else {
				log.Printf("Policy reloaded")
			}
		}
	}
}

type SMTPProxy struct {
	hostAdapter       *hostAdapter
	policy            atomic.Pointer[rules.Policy]
	sessions          sync.WaitGroup
	active            map[net.Conn]struct{}
	draining          bool
	upstreamConfig    upstreamConfig
	submission        bool
	listenAddr        string
	script            string
	scriptName        string
	runtime           *runtime
	upstreamServer    string
	tlsConfig         *tls.Config
	maxConnections    int
	forwardQuarantine bool
	connections       map[string]time.Time
	connMutex         sync.Mutex
	stats             *ProxyStats
}

type ProxyStats struct {
	StartTime         time.Time
	TotalConnections  int64
	ActiveConnections int64
	MessagesProcessed int64
	MessagesAccepted  int64
	MessagesRejected  int64
	BytesProcessed    int64
	sync.Mutex
}

// engineOptions returns the execution options for one message.
func (p *SMTPProxy) engineOptions() rules.Options {
	if p.runtime != nil {
		return p.runtime.engineOptions(p.scriptName)
	}
	opts := rules.DefaultOptions()
	opts.Filename = p.scriptName
	return opts
}

func (p *SMTPProxy) listenSMTP(port int) error {
	listener, err := net.Listen("tcp", net.JoinHostPort(p.listenAddr, strconv.Itoa(port)))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}
	defer listener.Close()

	return p.serveSMTP(listener)
}

func (p *SMTPProxy) serveSMTP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}

		p.stats.Lock()
		p.stats.TotalConnections++
		if p.maxConnections > 0 && p.stats.ActiveConnections >= int64(p.maxConnections) {
			p.stats.Unlock()
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			fmt.Fprint(conn, "421 Too many connections\r\n")
			conn.Close()
			continue
		}
		p.stats.ActiveConnections++
		p.stats.Unlock()

		p.connMutex.Lock()
		if p.draining {
			p.connMutex.Unlock()
			conn.Close()
			p.stats.Lock()
			p.stats.ActiveConnections--
			p.stats.Unlock()
			return net.ErrClosed
		}
		if p.active == nil {
			p.active = make(map[net.Conn]struct{})
		}
		p.active[conn] = struct{}{}
		p.sessions.Add(1)
		p.connMutex.Unlock()
		go func() {
			defer p.sessions.Done()
			defer func() { p.connMutex.Lock(); delete(p.active, conn); p.connMutex.Unlock() }()
			p.handleSMTPConnection(conn)
		}()
	}
}

func (p *SMTPProxy) handleSMTPConnection(conn net.Conn) {
	defer func() {
		conn.Close()
		p.stats.Lock()
		p.stats.ActiveConnections--
		p.stats.Unlock()
	}()

	remoteAddr := conn.RemoteAddr().String()
	if verbose {
		log.Printf("new connection from %s", remoteAddr)
	}

	// Track connection
	p.connMutex.Lock()
	if p.connections == nil {
		p.connections = make(map[string]time.Time)
	}
	p.connections[remoteAddr] = time.Now()
	p.connMutex.Unlock()
	defer func() { p.connMutex.Lock(); delete(p.connections, remoteAddr); p.connMutex.Unlock() }()

	session := &SMTPSession{
		conn:   conn,
		reader: bufio.NewReader(conn),
		proxy:  p,
	}
	if host, _, err := net.SplitHostPort(remoteAddr); err == nil {
		session.clientIP = host
	}

	defer session.closeUpstream()
	// Send greeting
	session.writeLine("220 MailScript SMTP Proxy ready")

	// Handle SMTP commands
	for {
		conn.SetDeadline(time.Now().Add(5 * time.Minute))
		line, err := readWireLine(session.reader, 4096)
		if err != nil {
			if err != io.EOF {
				log.Printf("Read error: %v", err)
			}
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) == 0 {
			continue
		}

		cmd := strings.ToUpper(parts[0])

		if verbose {
			if cmd != "AUTH" {
				log.Printf("<- %s: %s", remoteAddr, line)
			}
		}

		switch cmd {
		case "AUTH":
			session.handleAUTH(parts)
		case "HELO":
			session.handleHELO(parts)
		case "EHLO":
			session.handleEHLO(parts)
		case "MAIL":
			session.handleMAIL(line)
		case "RCPT":
			session.handleRCPT(line)
		case "DATA":
			session.handleDATA()
		case "RSET":
			session.handleRSET()
		case "NOOP":
			session.writeLine("250 OK")
		case "QUIT":
			session.writeLine("221 Bye")
			return
		case "STARTTLS":
			session.handleSTARTTLS()
		default:
			session.writeLine("500 Command not recognized")
		}
	}
}

type SMTPSession struct {
	actions    []string
	conn       net.Conn
	reader     *bufio.Reader
	proxy      *SMTPProxy
	from       string
	recipients []string
	data       []byte
	// helo is the name the client announced, and clientIP the address it
	// connected from. SPF authenticates the envelope against these, not
	// against anything inside the message.
	helo                   string
	clientIP               string
	mailSet                bool
	tlsActive              bool
	replyCode              int
	upstream               *upstreamTransaction
	authenticated          bool
	authUser, authPassword string
}

func (s *SMTPSession) writeLine(msg string) {
	if verbose {
		log.Printf("-> %s", msg)
	}
	s.conn.Write([]byte(msg + "\r\n"))
}

func (s *SMTPSession) handleHELO(parts []string) {
	if len(parts) < 2 {
		s.writeLine("501 Syntax: HELO hostname")
		return
	}
	s.resetTransaction()
	s.helo = parts[1]
	s.writeLine("250 MailScript SMTP Proxy")
}

func (s *SMTPSession) handleEHLO(parts []string) {
	if len(parts) < 2 {
		s.writeLine("501 Syntax: EHLO hostname")
		return
	}

	s.resetTransaction()
	s.helo = parts[1]
	s.writeLine("250-MailScript SMTP Proxy")
	s.writeLine("250-PIPELINING")
	s.writeLine("250-8BITMIME")
	if s.proxy.tlsConfig != nil && !s.tlsActive {
		s.writeLine("250-STARTTLS")
	}
	if s.proxy.submission && s.tlsActive && !s.authenticated {
		s.writeLine("250-AUTH PLAIN")
	}
	s.writeLine("250 SIZE 52428800") // 50MB max
}

func (s *SMTPSession) handleMAIL(line string) {
	if s.helo == "" {
		s.writeLine("503 Send HELO or EHLO first")
		return
	}
	if s.proxy.submission && !s.authenticated {
		s.writeLine("530 Authentication required")
		return
	}
	if s.mailSet {
		s.writeLine("503 Transaction already started")
		return
	}
	address, err := parseSMTPPath(line, "MAIL FROM:", true)
	if err != nil {
		s.writeLine("501 Invalid MAIL FROM")
		return
	}
	s.resetTransaction()
	s.from = address
	if s.proxy.upstreamServer != "" {
		if err := s.beginUpstream(); err != nil {
			s.resetTransaction()
			s.upstreamFailure(err)
			return
		}
	}
	s.mailSet = true
	s.writeLine("250 OK")
}

func (s *SMTPSession) handleRCPT(line string) {
	if !s.mailSet {
		s.writeLine("503 Send MAIL first")
		return
	}
	address, err := parseSMTPPath(line, "RCPT TO:", false)
	if err != nil {
		s.writeLine("501 Invalid RCPT TO")
		return
	}
	if len(s.recipients) >= 100 {
		s.writeLine("452 Too many recipients")
		return
	}
	if s.upstream != nil {
		code, text, err := s.upstream.command("RCPT TO:<"+address+">", 0)
		if err != nil {
			s.resetTransaction()
			s.upstreamFailure(err)
			return
		}
		if code != 250 && code != 251 && code != 252 {
			s.upstreamFailure(&upstreamError{code: code, stage: "RCPT TO", text: text})
			return
		}
	}
	s.recipients = append(s.recipients, address)
	s.writeLine("250 OK")
}

func (s *SMTPSession) handleDATA() {
	if !s.mailSet || len(s.recipients) == 0 {
		s.writeLine("503 Error: need MAIL command")
		return
	}

	defer s.resetTransaction()
	s.writeLine("354 End data with <CR><LF>.<CR><LF>")

	var data strings.Builder
	for {
		line, err := readWireLine(s.reader, 64*1024)
		if err != nil {
			log.Printf("DATA read error: %v", err)
			s.conn.Close()
			return
		}

		if !strings.HasSuffix(line, "\r\n") || strings.ContainsRune(strings.TrimSuffix(line, "\r\n"), '\r') {
			s.writeLine("550 DATA requires CRLF line endings")
			s.conn.Close()
			return
		}
		if line == ".\r\n" {
			break
		}

		if strings.HasPrefix(line, ".") {
			line = line[1:]
		}
		if data.Len()+len(line) > 50*1024*1024 {
			s.writeLine("552 Message too large")
			s.conn.Close()
			return
		}
		data.WriteString(line)
	}

	s.data = []byte(data.String())

	// Process with MailScript
	accepted, quarantined, reason := s.processWithMailScript()

	s.proxy.stats.Lock()
	s.proxy.stats.MessagesProcessed++
	s.proxy.stats.BytesProcessed += int64(len(s.data))
	if accepted {
		if quarantined {
			s.data = prependHeader(s.data, "X-MailScript-Quarantine", "true")
		}
	} else {
		s.proxy.stats.MessagesRejected++
	}
	s.proxy.stats.Unlock()

	if accepted {
		// Acceptance transfers responsibility only after upstream delivery.
		if err := s.deliver(context.Background()); err != nil {
			log.Printf("Upstream forward error: %v", err)
			s.proxy.stats.Lock()
			s.proxy.stats.MessagesRejected++
			s.proxy.stats.Unlock()
			// Relay the upstream's own status class back to the client. A
			// permanent rejection (5xx) must stay permanent so the sending
			// MTA bounces instead of retrying for days; only fall back to a
			// temporary 450 for connection-level failures where we never
			// learned the upstream's verdict.
			var ue *upstreamError
			if errors.As(err, &ue) && ue.code >= 400 && ue.code < 600 {
				s.writeLine(ue.clientReply())
			} else {
				s.writeLine("450 Temporary failure")
			}
			return
		}
		s.proxy.stats.Lock()
		s.proxy.stats.MessagesAccepted++
		s.proxy.stats.Unlock()
		s.writeLine("250 OK: Message accepted")
	} else {
		code := s.replyCode
		if code == 0 {
			code = 550
		}
		s.writeLine(fmt.Sprintf("%d %s", code, smtpReplyText(reason)))
	}

}

func (s *SMTPSession) processWithMailScript() (bool, bool, string) {
	// This header is a private proxy-to-upstream control signal. A public SMTP
	// client must never be able to set it and get a message routed to a
	// quarantine mailbox, so remove any client-supplied copy before parsing or
	// forwarding. The proxy adds a fresh copy only after its own rule decides.
	s.data = stripHeader(s.data, "X-MailScript-Quarantine")

	// Parse with the full message parser rather than splitting on colons.
	// A hand-rolled map would collapse duplicate fields, discard the original
	// bytes, and skip MIME decoding, which would silently disable duplicate
	// From detection, DKIM verification and attachment inspection.
	ctx, err := rules.ParseMessage(s.data)
	if err != nil {
		log.Printf("message parse error: %v", err)
		return false, false, "Message could not be parsed"
	}

	// Envelope and connection facts the message itself cannot be trusted for.
	ctx.EnvelopeFrom = s.from
	ctx.EnvelopeTo = s.recipients
	ctx.EnvelopeSenders = []string{s.from}
	ctx.HELO = s.helo
	if s.clientIP != "" {
		ctx.SenderIP = s.clientIP
	}
	ctx.VirusStatus = "unknown"

	if rt := s.proxy.runtime; rt != nil {
		rt.apply(ctx)
	}

	// Execute script
	if err := s.proxy.executePolicy(ctx); err != nil {
		log.Printf("MailScript error: %v", err)
		s.replyCode = 451
		return false, false, "Script execution error"
	}
	s.data = applyHeaderChanges(s.data, ctx.RemovedHeaders, ctx.ModifiedHeaders)

	s.actions = append([]string(nil), ctx.Actions...)
	d := policyDisposition(ctx.Actions, s.proxy.forwardQuarantine || s.proxy.hostAdapter != nil)
	if action := unsupportedDeliveryAction(ctx.Actions); d.code == 250 && action != "" && s.proxy.hostAdapter == nil {
		d = deliveryDisposition{code: 451, reason: "Delivery action requires a host adapter: " + action}
	}
	s.replyCode = d.code
	return d.code == 250, d.quarantine, d.reason
}

func stripHeader(raw []byte, name string) []byte {
	lines := strings.SplitAfter(string(raw), "\n")
	filtered := make([]string, 0, len(lines))
	skipping := false
	inHeaders := true
	for _, line := range lines {
		if inHeaders && strings.TrimRight(line, "\r\n") == "" {
			inHeaders = false
			skipping = false
			filtered = append(filtered, line)
			continue
		}
		if !inHeaders {
			filtered = append(filtered, line)
			continue
		}
		if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
			if skipping {
				continue
			}
			filtered = append(filtered, line)
			continue
		}
		skipping = false
		parts := strings.SplitN(strings.TrimRight(line, "\r\n"), ":", 2)
		if len(parts) == 2 && strings.EqualFold(strings.TrimSpace(parts[0]), name) {
			skipping = true
			continue
		}
		filtered = append(filtered, line)
	}
	return []byte(strings.Join(filtered, ""))
}

func prependHeader(raw []byte, name, value string) []byte {
	return append([]byte(name+": "+value+"\r\n"), raw...)
}

func applyModifiedHeaders(raw []byte, headers map[string]string) []byte {
	names := make([]string, 0, len(headers))
	for name := range headers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		raw = prependHeader(raw, name, headers[name])
	}
	return raw
}

func applyHeaderChanges(raw []byte, removed []string, added map[string]string) []byte {
	for _, name := range removed {
		raw = stripHeader(raw, name)
	}
	return applyModifiedHeaders(raw, added)
}

// upstreamError carries the SMTP status the upstream returned so the proxy can
// relay the correct class (permanent vs temporary) back to the client instead
// of flattening every failure to a generic 450.
type upstreamError struct {
	code  int
	stage string
	text  string
}

func (e *upstreamError) Error() string {
	return fmt.Sprintf("upstream rejected at %s: %d %s", e.stage, e.code, smtpReplyText(e.message()))
}

// message returns the human-readable text of the upstream reply with the
// leading status code stripped, so callers can re-emit "<code> <message>"
// without duplicating the number. Multi-line replies collapse to their final
// line, which carries the summary.
func (e *upstreamError) message() string {
	last := strings.TrimSpace(e.text)
	if i := strings.LastIndex(last, "\n"); i != -1 {
		last = strings.TrimSpace(last[i+1:])
	}
	// Strip a leading "NNN" or "NNN-"/"NNN " code token if present.
	if len(last) >= 3 {
		if _, err := strconv.Atoi(last[:3]); err == nil {
			last = strings.TrimSpace(strings.TrimLeft(last[3:], "- "))
		}
	}
	if last == "" {
		last = "rejected by upstream"
	}
	return last
}

// clientReply renders the SMTP line to send back to the client, preserving the
// upstream's status code so permanent vs temporary class is not lost.
func (e *upstreamError) clientReply() string {
	return fmt.Sprintf("%d %s", e.code, smtpReplyText(e.message()))
}

// readSMTPReply reads one complete SMTP reply, following multi-line
// continuations ("250-line" ... "250 line"), and returns the numeric code.
// Reading a single line, as the old code did, would desync the protocol
// stream the moment an upstream sent a multi-line MAIL FROM/RCPT/DATA reply.
func readSMTPReply(reader *bufio.Reader) (int, string, error) {
	var full strings.Builder
	expected := 0
	for {
		line, err := readWireLine(reader, 4096)
		if err != nil {
			return 0, "", err
		}
		if full.Len()+len(line) > 64*1024 {
			return 0, "", fmt.Errorf("SMTP reply too large")
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if len(trimmed) < 3 {
			return 0, "", fmt.Errorf("malformed SMTP reply")
		}
		code, parseErr := strconv.Atoi(trimmed[:3])
		if parseErr != nil || code < 200 || code > 599 || (len(trimmed) > 3 && trimmed[3] != ' ' && trimmed[3] != '-') {
			return 0, "", fmt.Errorf("malformed SMTP reply")
		}
		if expected != 0 && code != expected {
			return 0, "", fmt.Errorf("inconsistent SMTP reply codes")
		}
		expected = code
		full.WriteString(line)
		// A continuation line has a '-' as the 4th character; the final line
		// has a space (or is too short to continue).
		if len(line) < 4 || line[3] != '-' {
			code := 0
			if len(line) >= 3 {
				code, _ = strconv.Atoi(line[:3])
			}
			return code, full.String(), nil
		}
	}
}

func dotStuff(raw []byte) []byte {
	// SMTP transparency: every data line beginning with a dot gains one dot.
	out := make([]byte, 0, len(raw)+16)
	atLineStart := true
	for _, b := range raw {
		if atLineStart && b == '.' {
			out = append(out, '.')
		}
		out = append(out, b)
		atLineStart = b == '\n'
	}
	return out
}

func (s *SMTPSession) resetTransaction() {
	s.closeUpstream()
	s.from = ""
	s.recipients = nil
	s.data = nil
	s.mailSet = false
	s.replyCode = 0
	s.actions = nil
}

func (s *SMTPSession) handleRSET() {
	s.resetTransaction()
	s.writeLine("250 OK")
}

func (s *SMTPSession) handleSTARTTLS() {
	if s.proxy.tlsConfig == nil || s.tlsActive {
		s.writeLine("454 TLS not available")
		return
	}

	s.writeLine("220 Ready to start TLS")

	tlsConn := tls.Server(s.conn, s.proxy.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		s.conn.Close()
		return
	}

	s.resetTransaction()
	s.helo = ""
	s.authenticated = false
	s.authUser, s.authPassword = "", ""
	s.tlsActive = true
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	log.Printf("TLS connection established")
}

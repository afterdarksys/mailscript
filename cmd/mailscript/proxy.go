package main

import (
	"bufio"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
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

Examples:
  # Run SMTP proxy on ports 3025 and 3587
  mailscript proxy --script=filter.star --port=3025,3587

  # Enable TLS
  mailscript proxy --script=filter.star --enable-tls --cert=cert.pem --key=key.pem

  # Disable TLS
  mailscript proxy --script=filter.star --disable-tls

  # Forward to upstream server
  mailscript proxy --script=filter.star --upstream=mail.example.com:25

  # Custom gRPC port
  mailscript proxy --script=filter.star --grpc-port=50051
`,
	RunE: runProxy,
}

var (
	proxyPorts     []int
	enableTLS      bool
	disableTLS     bool
	certFile       string
	keyFile        string
	upstreamServer string
	grpcPort       int
	maxConnections int
)

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
	proxyCmd.Flags().IntVar(&maxConnections, "max-connections", 100, "Maximum concurrent connections")

	proxyCmd.MarkFlagRequired("script")
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Read script
	scriptContent, err := os.ReadFile(scriptPath)
	if err != nil {
		return fmt.Errorf("failed to read script: %w", err)
	}

	proxy := &SMTPProxy{
		script:         string(scriptContent),
		upstreamServer: upstreamServer,
		maxConnections: maxConnections,
		connections:    make(map[string]time.Time),
		stats: &ProxyStats{
			StartTime: time.Now(),
		},
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
		fmt.Println("🔒 TLS enabled")
	} else if disableTLS {
		fmt.Println("⚠️  TLS disabled - running in plaintext mode")
	}

	// Start gRPC server
	go func() {
		if err := proxy.startGRPCServer(grpcPort); err != nil {
			log.Printf("❌ gRPC server error: %v", err)
		}
	}()

	// Start SMTP listeners
	var wg sync.WaitGroup
	for _, port := range proxyPorts {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if err := proxy.listenSMTP(p); err != nil {
				log.Printf("❌ SMTP listener error on port %d: %v", p, err)
			}
		}(port)
	}

	fmt.Printf("🚀 MailScript SMTP Proxy started\n")
	fmt.Printf("📝 Script: %s\n", scriptPath)
	fmt.Printf("📬 SMTP ports: %v\n", proxyPorts)
	fmt.Printf("🔌 gRPC port: %d\n", grpcPort)
	if upstreamServer != "" {
		fmt.Printf("⬆️  Upstream: %s\n", upstreamServer)
	}
	fmt.Println()
	fmt.Println("Press Ctrl+C to stop")

	wg.Wait()
	return nil
}

type SMTPProxy struct {
	script         string
	upstreamServer string
	tlsConfig      *tls.Config
	maxConnections int
	connections    map[string]time.Time
	connMutex      sync.Mutex
	stats          *ProxyStats
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

func (p *SMTPProxy) listenSMTP(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("failed to listen on port %d: %w", port, err)
	}
	defer listener.Close()

	log.Printf("📬 SMTP listening on port %d", port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		p.stats.Lock()
		p.stats.TotalConnections++
		p.stats.ActiveConnections++
		p.stats.Unlock()

		go p.handleSMTPConnection(conn)
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
		log.Printf("📨 New connection from %s", remoteAddr)
	}

	// Track connection
	p.connMutex.Lock()
	p.connections[remoteAddr] = time.Now()
	p.connMutex.Unlock()

	session := &SMTPSession{
		conn:   conn,
		reader: bufio.NewReader(conn),
		proxy:  p,
	}

	// Send greeting
	session.writeLine("220 MailScript SMTP Proxy ready")

	// Handle SMTP commands
	for {
		line, err := session.reader.ReadString('\n')
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
			log.Printf("← %s: %s", remoteAddr, line)
		}

		switch cmd {
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
	conn      net.Conn
	reader    *bufio.Reader
	proxy     *SMTPProxy
	from      string
	recipients []string
	data      []byte
}

func (s *SMTPSession) writeLine(msg string) {
	if verbose {
		log.Printf("→ %s", msg)
	}
	s.conn.Write([]byte(msg + "\r\n"))
}

func (s *SMTPSession) handleHELO(parts []string) {
	if len(parts) < 2 {
		s.writeLine("501 Syntax: HELO hostname")
		return
	}
	s.writeLine("250 MailScript SMTP Proxy")
}

func (s *SMTPSession) handleEHLO(parts []string) {
	if len(parts) < 2 {
		s.writeLine("501 Syntax: EHLO hostname")
		return
	}

	s.writeLine("250-MailScript SMTP Proxy")
	s.writeLine("250-PIPELINING")
	s.writeLine("250-8BITMIME")
	if s.proxy.tlsConfig != nil {
		s.writeLine("250-STARTTLS")
	}
	s.writeLine("250 SIZE 52428800") // 50MB max
}

func (s *SMTPSession) handleMAIL(line string) {
	// Extract email from MAIL FROM:<email>
	start := strings.Index(line, "<")
	end := strings.Index(line, ">")
	if start == -1 || end == -1 {
		s.writeLine("501 Syntax: MAIL FROM:<address>")
		return
	}

	s.from = line[start+1 : end]
	s.writeLine("250 OK")
}

func (s *SMTPSession) handleRCPT(line string) {
	start := strings.Index(line, "<")
	end := strings.Index(line, ">")
	if start == -1 || end == -1 {
		s.writeLine("501 Syntax: RCPT TO:<address>")
		return
	}

	recipient := line[start+1 : end]
	s.recipients = append(s.recipients, recipient)
	s.writeLine("250 OK")
}

func (s *SMTPSession) handleDATA() {
	if s.from == "" || len(s.recipients) == 0 {
		s.writeLine("503 Error: need MAIL command")
		return
	}

	s.writeLine("354 End data with <CR><LF>.<CR><LF>")

	var data strings.Builder
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			log.Printf("DATA read error: %v", err)
			return
		}

		if line == ".\r\n" || line == ".\n" {
			break
		}

		data.WriteString(line)
	}

	s.data = []byte(data.String())

	// Process with MailScript
	accepted, reason := s.processWithMailScript()

	s.proxy.stats.Lock()
	s.proxy.stats.MessagesProcessed++
	s.proxy.stats.BytesProcessed += int64(len(s.data))
	if accepted {
		s.proxy.stats.MessagesAccepted++
	} else {
		s.proxy.stats.MessagesRejected++
	}
	s.proxy.stats.Unlock()

	if accepted {
		// Forward to upstream if configured
		if s.proxy.upstreamServer != "" {
			if err := s.forwardToUpstream(); err != nil {
				log.Printf("Upstream forward error: %v", err)
				s.writeLine("450 Temporary failure")
				return
			}
		}
		s.writeLine("250 OK: Message accepted")
	} else {
		s.writeLine(fmt.Sprintf("550 Rejected: %s", reason))
	}

	// Reset for next message
	s.from = ""
	s.recipients = nil
	s.data = nil
}

func (s *SMTPSession) processWithMailScript() (bool, string) {
	// Parse message headers
	headers := make(map[string]string)
	lines := strings.Split(string(s.data), "\n")

	var body strings.Builder
	inHeaders := true

	for _, line := range lines {
		line = strings.TrimRight(line, "\r")

		if inHeaders {
			if line == "" {
				inHeaders = false
				continue
			}

			if strings.Contains(line, ":") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) == 2 {
					headers[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
				}
			}
		} else {
			body.WriteString(line)
			body.WriteString("\n")
		}
	}

	// Add envelope info
	headers["X-Envelope-From"] = s.from
	headers["X-Envelope-To"] = strings.Join(s.recipients, ", ")

	// Create message context
	ctx := &rules.MessageContext{
		Headers:         headers,
		Body:            body.String(),
		MimeType:        headers["Content-Type"],
		SpamScore:       0.0,
		VirusStatus:     "clean",
		Actions:         []string{},
		LogEntries:      []string{},
		ModifiedHeaders: make(map[string]string),
		SenderDomain:    extractDomain(s.from),
		DNSResolved:     true,
		RBLListed:       false,
	}

	// Execute script
	if err := rules.ExecuteEngine(s.proxy.script, ctx); err != nil {
		log.Printf("MailScript error: %v", err)
		return false, "Script execution error"
	}

	// Check actions
	for _, action := range ctx.Actions {
		switch {
		case action == "discard":
			return false, "Message discarded by filter"
		case action == "quarantine":
			return false, "Message quarantined"
		case strings.HasPrefix(action, "fileinto:Spam"):
			return false, "Classified as spam"
		case action == "bounce":
			return false, "Message bounced"
		case action == "drop":
			return false, "Message dropped"
		}
	}

	// Default accept
	return true, ""
}

func (s *SMTPSession) forwardToUpstream() error {
	if s.proxy.upstreamServer == "" {
		return nil
	}

	log.Printf("⬆️  Forwarding to upstream: %s", s.proxy.upstreamServer)

	// Connect to upstream server
	conn, err := net.DialTimeout("tcp", s.proxy.upstreamServer, 30*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to upstream: %w", err)
	}
	defer conn.Close()

	reader := bufio.NewReader(conn)

	// Read greeting
	greeting, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("failed to read upstream greeting: %w", err)
	}
	if verbose {
		log.Printf("Upstream greeting: %s", strings.TrimSpace(greeting))
	}

	// Send EHLO
	fmt.Fprintf(conn, "EHLO mailscript-proxy\r\n")
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return fmt.Errorf("EHLO response error: %w", err)
		}
		if verbose {
			log.Printf("← %s", strings.TrimSpace(line))
		}
		if !strings.HasPrefix(line, "250-") {
			break
		}
	}

	// Send MAIL FROM
	fmt.Fprintf(conn, "MAIL FROM:<%s>\r\n", s.from)
	if _, err := reader.ReadString('\n'); err != nil {
		return fmt.Errorf("MAIL FROM error: %w", err)
	}

	// Send RCPT TO for each recipient
	for _, rcpt := range s.recipients {
		fmt.Fprintf(conn, "RCPT TO:<%s>\r\n", rcpt)
		if _, err := reader.ReadString('\n'); err != nil {
			return fmt.Errorf("RCPT TO error: %w", err)
		}
	}

	// Send DATA
	fmt.Fprintf(conn, "DATA\r\n")
	if _, err := reader.ReadString('\n'); err != nil {
		return fmt.Errorf("DATA command error: %w", err)
	}

	// Send message data
	conn.Write(s.data)
	fmt.Fprintf(conn, "\r\n.\r\n")

	// Wait for response
	response, err := reader.ReadString('\n')
	if err != nil {
		return fmt.Errorf("DATA response error: %w", err)
	}

	if !strings.HasPrefix(response, "250") {
		return fmt.Errorf("upstream rejected message: %s", response)
	}

	// Send QUIT
	fmt.Fprintf(conn, "QUIT\r\n")

	log.Printf("✅ Message forwarded successfully to upstream")
	return nil
}

func (s *SMTPSession) handleRSET() {
	s.from = ""
	s.recipients = nil
	s.data = nil
	s.writeLine("250 OK")
}

func (s *SMTPSession) handleSTARTTLS() {
	if s.proxy.tlsConfig == nil {
		s.writeLine("454 TLS not available")
		return
	}

	s.writeLine("220 Ready to start TLS")

	tlsConn := tls.Server(s.conn, s.proxy.tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("TLS handshake error: %v", err)
		return
	}

	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	log.Printf("🔒 TLS connection established")
}


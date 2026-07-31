package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
	"github.com/afterdarksys/mailscript/pkg/ml"
	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

// Build information, set via ldflags.
var (
	Version   = "dev"
	BuildTime = "unknown"
	GoVersion = "unknown"
)

// Shared runtime options, registered on commands that execute rules.
var (
	enableDNS        bool
	dnsServer        string
	dnsTimeout       time.Duration
	rblZones         []string
	modelPaths       []string
	bertVocabPath    string
	listPaths        []string
	trustedAuthServ  []string
	verifyAuth       bool
	checkDANE        bool
	clientIP         string
	heloName         string
	maxSteps         uint64
	scriptTimeout    time.Duration
	clamAVAddr       string
	clamAVTimeout    time.Duration
	clamAVMaxBytes   int64
	yaraURL          string
	yaraTimeout      time.Duration
	yaraMaxBytes     int64
	analyzerSpecs    []string
	analyzerTimeout  time.Duration
	analyzerMaxBytes int64
)

// addRuntimeFlags registers the flags shared by every rule-executing command.
func addRuntimeFlags(cmd *cobra.Command) {
	f := cmd.Flags()

	f.BoolVar(&enableDNS, "dns", false,
		"Enable DNS lookups (MX, TXT, PTR, RBL). Off by default so rules stay offline-deterministic")
	f.StringVar(&dnsServer, "dns-server", "",
		"DNS server as host:port. For DANE this must be a DNSSEC-validating resolver")
	f.DurationVar(&dnsTimeout, "dns-timeout", 3*time.Second, "Per-query DNS timeout")
	f.StringSliceVar(&rblZones, "rbl", nil, "DNSBL zones to consult (default: Spamhaus, SpamCop, Barracuda)")

	f.StringSliceVar(&modelPaths, "model", nil,
		"Classification model to load, as path or name=path. Repeatable")
	f.StringVar(&bertVocabPath, "bert-vocab", "", "WordPiece vocab.txt for the BERT tokenizer builtins")
	f.StringSliceVar(&listPaths, "list", nil,
		"Named list file, as name=path. One entry per line, '#' comments. Repeatable")

	f.StringSliceVar(&trustedAuthServ, "trusted-authserv", nil,
		"authserv-id values this deployment writes. Authentication-Results from any other authority is never trusted")
	f.BoolVar(&verifyAuth, "verify", false,
		"Cryptographically verify SPF, DKIM, DMARC and ARC instead of reading Authentication-Results. Implies --dns")
	f.BoolVar(&checkDANE, "dane", false, "Also check DANE TLSA records for the sender domain. Implies --verify")

	f.StringVar(&clientIP, "client-ip", "", "Connecting client address, required for SPF evaluation")
	f.StringVar(&heloName, "helo", "", "HELO name the client announced")

	f.Uint64Var(&maxSteps, "max-steps", rules.DefaultMaxSteps, "Starlark execution step limit per message")
	f.DurationVar(&scriptTimeout, "script-timeout", rules.DefaultTimeout, "Wall-clock limit per message")
	f.StringVar(&clamAVAddr, "clamav-addr", "", "clamd daemon address for native INSTREAM scanning (host:port, e.g. 127.0.0.1:3310)")
	f.DurationVar(&clamAVTimeout, "clamav-timeout", 30*time.Second, "Maximum ClamAV scan duration")
	f.Int64Var(&clamAVMaxBytes, "clamav-max-bytes", 26214400, "Maximum RFC 822 message size sent to clamd (0 disables limit)")
	f.StringVar(&yaraURL, "yara-url", "", "Private YARA scanner sidecar base URL (POST /v1/scan)")
	f.DurationVar(&yaraTimeout, "yara-timeout", 30*time.Second, "Maximum YARA scan duration")
	f.Int64Var(&yaraMaxBytes, "yara-max-bytes", 26214400, "Maximum RFC 822 message size sent to the YARA scanner (0 disables limit)")
	f.StringSliceVar(&analyzerSpecs, "analyzer", nil, "Analysis sidecar as name=URL; repeatable (POST /v1/analyze)")
	f.DurationVar(&analyzerTimeout, "analyzer-timeout", 30*time.Second, "Maximum duration for each analysis sidecar")
	f.Int64Var(&analyzerMaxBytes, "analyzer-max-bytes", 26214400, "Maximum RFC 822 message size sent to an analyzer (0 disables limit)")
}

// runtime holds the resources built from the shared flags.
type runtime struct {
	resolver  *dnsx.Resolver
	models    *ml.Registry
	bert      *ml.BertTokenizer
	lists     map[string]map[string]bool
	clamav    *clamAVScanner
	yara      *yaraScanner
	analyzers []*analyzerClient
}

// buildRuntime constructs the shared resources, failing closed on any
// misconfiguration rather than silently running with a feature disabled.
func buildRuntime() (*runtime, error) {
	rt := &runtime{lists: map[string]map[string]bool{}}

	// DANE implies verification, which implies DNS.
	if checkDANE {
		verifyAuth = true
	}
	if verifyAuth {
		enableDNS = true
	}

	if enableDNS {
		opts := []dnsx.ResolverOption{dnsx.WithTimeout(dnsTimeout)}
		if dnsServer != "" {
			opts = append(opts, dnsx.WithNameserver(dnsServer), dnsx.WithRawNameserver(dnsServer))
		}
		if len(rblZones) > 0 {
			opts = append(opts, dnsx.WithRBLs(rblZones))
		}
		rt.resolver = dnsx.NewResolver(opts...)
	}

	if len(modelPaths) > 0 {
		rt.models = ml.NewRegistry()
		for _, spec := range modelPaths {
			name, path := splitNameSpec(spec)
			if err := rt.models.LoadFile(name, path); err != nil {
				return nil, fmt.Errorf("load model %q: %w", path, err)
			}
		}
	}
	if clamAVAddr != "" {
		if _, _, err := net.SplitHostPort(clamAVAddr); err != nil {
			return nil, fmt.Errorf("--clamav-addr must be host:port (e.g. 127.0.0.1:3310): %w", err)
		}
		rt.clamav = newClamAVScanner(clamAVAddr, clamAVTimeout, clamAVMaxBytes)
	}
	if yaraURL != "" {
		rt.yara = newYARAScanner(yaraURL, yaraTimeout, yaraMaxBytes)
	}
	seenAnalyzers := make(map[string]struct{}, len(analyzerSpecs))
	for _, spec := range analyzerSpecs {
		name, endpoint := splitNameSpec(spec)
		if !validAnalyzerName(name) || !validAnalyzerEndpoint(endpoint) {
			return nil, fmt.Errorf("analyzer %q must be name=URL using letters, digits, '.', '_' or '-'", spec)
		}
		if _, exists := seenAnalyzers[name]; exists {
			return nil, fmt.Errorf("duplicate analyzer name %q", name)
		}
		seenAnalyzers[name] = struct{}{}
		rt.analyzers = append(rt.analyzers, newAnalyzerClient(name, endpoint, analyzerTimeout, analyzerMaxBytes))
	}

	if bertVocabPath != "" {
		tokenizer, err := ml.LoadBertVocab(bertVocabPath, true)
		if err != nil {
			return nil, err
		}
		rt.bert = tokenizer
	}

	for _, spec := range listPaths {
		name, path := splitNameSpec(spec)
		if name == "" {
			return nil, fmt.Errorf("list %q must be given as name=path", spec)
		}
		entries, err := loadList(path)
		if err != nil {
			return nil, fmt.Errorf("load list %q: %w", path, err)
		}
		rt.lists[name] = entries
	}

	return rt, nil
}

// splitNameSpec parses a "name=path" specification, returning an empty name
// when only a path was given.
func splitNameSpec(spec string) (name, path string) {
	if i := strings.Index(spec, "="); i > 0 {
		return spec[:i], spec[i+1:]
	}
	return "", spec
}

// loadList reads a newline-delimited list file, lowercasing entries and
// skipping blanks and comments.
func loadList(path string) (map[string]bool, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	entries := map[string]bool{}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries[strings.ToLower(line)] = true
	}
	return entries, scanner.Err()
}

// engineOptions builds the execution options from the runtime.
func (rt *runtime) engineOptions(filename string) rules.Options {
	opts := rules.DefaultOptions()
	opts.Filename = filename
	opts.MaxSteps = maxSteps
	opts.Timeout = scriptTimeout
	opts.Models = rt.models
	opts.BertTokenizer = rt.bert
	return opts
}

// apply attaches the runtime resources to a message context.
func (rt *runtime) apply(ctx *rules.MessageContext) {
	ctx.Resolver = rt.resolver
	ctx.Lists = rt.lists
	ctx.TrustedAuthServs = trustedAuthServ
	if rt.clamav != nil {
		result, err := rt.clamav.scan(context.Background(), rawMessage(ctx))
		if err != nil {
			ctx.VirusStatus = "unknown"
			ctx.LogEntries = append(ctx.LogEntries, "clamav unavailable: "+err.Error())
		} else {
			ctx.AVAvailable = true
			if result.VirusFound {
				ctx.VirusStatus = "infected"
				ctx.AVSignature = result.Signature
			} else {
				ctx.VirusStatus = "clean"
			}
		}
	}
	if rt.yara != nil {
		matches, err := rt.yara.scan(context.Background(), rawMessage(ctx))
		if err != nil {
			ctx.LogEntries = append(ctx.LogEntries, "yara unavailable: "+err.Error())
		} else {
			ctx.YARAAvailable = true
			ctx.YARAMatches = matches
		}
	}
	rt.applyAnalyzers(ctx, rawMessage(ctx))

	if clientIP != "" {
		ctx.SenderIP = clientIP
	}
	if heloName != "" {
		ctx.HELO = heloName
	}

	// Run verification eagerly so its cost is paid once and the result is
	// available to every builtin that reads it.
	if verifyAuth && rt.resolver != nil {
		ctx.VerifyAuth(checkDANE)
	}
}

// applyAnalyzers runs independent sidecars concurrently but appends their
// results and errors in configuration order for deterministic policy output.
func (rt *runtime) applyAnalyzers(ctx *rules.MessageContext, raw []byte) {
	type outcome struct {
		result rules.AnalyzerResult
		err    error
	}
	outcomes := make([]outcome, len(rt.analyzers))
	var wg sync.WaitGroup
	for i, analyzer := range rt.analyzers {
		i, analyzer := i, analyzer
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcomes[i].result, outcomes[i].err = analyzer.analyze(context.Background(), raw)
		}()
	}
	wg.Wait()
	for i, outcome := range outcomes {
		if outcome.err != nil {
			ctx.LogEntries = append(ctx.LogEntries, "analyzer "+rt.analyzers[i].name+" unavailable: "+outcome.err.Error())
			continue
		}
		ctx.AnalyzerResults = append(ctx.AnalyzerResults, outcome.result)
	}
}

func validAnalyzerName(name string) bool {
	if name == "" {
		return false
	}
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '.' || r == '_' || r == '-' {
			continue
		}
		return false
	}
	return true
}

func validAnalyzerEndpoint(endpoint string) bool {
	parsed, err := url.ParseRequestURI(endpoint)
	return err == nil && (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func rawMessage(ctx *rules.MessageContext) []byte {
	raw := make([]byte, 0, len(ctx.RawHeaderBlock)+len(ctx.RawBody)+4)
	raw = append(raw, ctx.RawHeaderBlock...)
	raw = append(raw, '\r', '\n', '\r', '\n')
	raw = append(raw, ctx.RawBody...)
	return raw
}

// readScript loads a rule script, searching the standard locations when no
// explicit path was given.
func readScript(path string) (string, string, error) {
	candidates := []string{path}
	if path == "" {
		home, _ := os.UserHomeDir()
		candidates = []string{
			"mailscript.star",
			"./mailscript.star",
			home + "/.config/mailscript/default.star",
			"/etc/mailscript/default.star",
		}
	}

	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		content, err := os.ReadFile(candidate)
		if err == nil {
			return string(content), candidate, nil
		}
		if path != "" {
			return "", "", fmt.Errorf("failed to read script %q: %w", candidate, err)
		}
	}

	return "", "", fmt.Errorf("no script found; pass --script or create ./mailscript.star")
}

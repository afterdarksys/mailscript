package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
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
	enableDNS       bool
	dnsServer       string
	dnsTimeout      time.Duration
	rblZones        []string
	modelPaths      []string
	bertVocabPath   string
	listPaths       []string
	trustedAuthServ []string
	verifyAuth      bool
	checkDANE       bool
	clientIP        string
	heloName        string
	maxSteps        uint64
	scriptTimeout   time.Duration
	clamAVURL       string
	clamAVTimeout   time.Duration
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
		"Cryptographically verify SPF, DKIM and DMARC instead of reading Authentication-Results. Implies --dns")
	f.BoolVar(&checkDANE, "dane", false, "Also check DANE TLSA records for the sender domain. Implies --verify")

	f.StringVar(&clientIP, "client-ip", "", "Connecting client address, required for SPF evaluation")
	f.StringVar(&heloName, "helo", "", "HELO name the client announced")

	f.Uint64Var(&maxSteps, "max-steps", rules.DefaultMaxSteps, "Starlark execution step limit per message")
	f.DurationVar(&scriptTimeout, "script-timeout", rules.DefaultTimeout, "Wall-clock limit per message")
	f.StringVar(&clamAVURL, "clamav-url", "", "Private clamav-api-go base URL (e.g. http://clamav-api:8080)")
	f.DurationVar(&clamAVTimeout, "clamav-timeout", 30*time.Second, "Maximum ClamAV scan duration")
}

// runtime holds the resources built from the shared flags.
type runtime struct {
	resolver *dnsx.Resolver
	models   *ml.Registry
	bert     *ml.BertTokenizer
	lists    map[string]map[string]bool
	clamav   *clamAVScanner
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
	if clamAVURL != "" {
		rt.clamav = newClamAVScanner(strings.TrimRight(clamAVURL, "/"), clamAVTimeout)
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
		result, err := rt.clamav.scan(context.Background(), append(append([]byte{}, ctx.RawHeaderBlock...), ctx.RawBody...))
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

package rules

import "github.com/afterdarksys/mailscript/pkg/dnsx"

// The DNS client lives in pkg/dnsx so that the authentication verifiers can
// share it without importing the rules engine. These aliases keep the
// resolver types reachable under their original names for callers that embed
// a resolver in a MessageContext.
type (
	// Resolver performs cached DNS and blocklist lookups. A nil value means
	// no network access, and every lookup reports a miss.
	Resolver = dnsx.Resolver

	// ResolverOption configures a Resolver.
	ResolverOption = dnsx.ResolverOption

	// RBLResult is the outcome of a single DNSBL query.
	RBLResult = dnsx.RBLResult

	// TLSAResult is the outcome of a DANE TLSA lookup.
	TLSAResult = dnsx.TLSAResult
)

// Resolver constructors and options, re-exported for convenience.
var (
	NewResolver       = dnsx.NewResolver
	WithTimeout       = dnsx.WithTimeout
	WithCacheTTL      = dnsx.WithCacheTTL
	WithRBLs          = dnsx.WithRBLs
	WithNameserver    = dnsx.WithNameserver
	WithRawNameserver = dnsx.WithRawNameserver

	// IsPrivateIP reports whether an address is loopback, private, or
	// link-local.
	IsPrivateIP = dnsx.IsPrivateIP

	// DefaultRBLs lists the blocklist zones consulted when none is named.
	DefaultRBLs = dnsx.DefaultRBLs
)

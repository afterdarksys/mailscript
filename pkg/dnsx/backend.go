package dnsx

import (
	"context"

	"sort"
	"strings"
	"sync"
)

// Backend performs the underlying DNS queries. Separating it from Resolver
// keeps the caching, limit and blocklist logic testable without a network:
// the authentication verifiers are only meaningful if their failure paths can
// be exercised deterministically.
type Backend interface {
	LookupHost(host string) ([]string, error)
	LookupMX(domain string) ([]string, error)
	LookupTXT(name string) ([]string, error)
	LookupPTR(ip string) ([]string, error)
}

// WithBackend replaces the query backend, primarily for tests.
func WithBackend(b Backend) ResolverOption {
	return func(r *Resolver) {
		r.queryBackend = b
	}
}

// backend returns the configured backend, defaulting to the system resolver.
func (r *Resolver) backend() Backend {
	if r.queryBackend != nil {
		return r.queryBackend
	}
	return &netBackend{resolver: r}
}

// netBackend queries the network through the standard library resolver.
type netBackend struct {
	resolver *Resolver
}

func (n *netBackend) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), n.resolver.timeout)
}

func (n *netBackend) LookupHost(host string) ([]string, error) {
	ctx, cancel := n.ctx()
	defer cancel()
	addrs, err := n.resolver.netres.LookupHost(ctx, host)
	sort.Strings(addrs)
	return addrs, err
}

func (n *netBackend) LookupMX(domain string) ([]string, error) {
	ctx, cancel := n.ctx()
	defer cancel()
	records, err := n.resolver.netres.LookupMX(ctx, domain)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })

	hosts := make([]string, 0, len(records))
	for _, mx := range records {
		hosts = append(hosts, strings.TrimSuffix(mx.Host, "."))
	}
	return hosts, nil
}

func (n *netBackend) LookupTXT(name string) ([]string, error) {
	ctx, cancel := n.ctx()
	defer cancel()
	return n.resolver.netres.LookupTXT(ctx, name)
}

func (n *netBackend) LookupPTR(ip string) ([]string, error) {
	ctx, cancel := n.ctx()
	defer cancel()
	names, err := n.resolver.netres.LookupAddr(ctx, ip)
	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}
	return names, err
}

// StaticBackend answers from an in-memory zone. Names are matched
// case-insensitively; anything absent resolves to an empty answer, which is
// how a real resolver reports NXDOMAIN to this layer.
type StaticBackend struct {
	mu sync.RWMutex

	Hosts map[string][]string
	MX    map[string][]string
	TXT   map[string][]string
	// SecureTXT marks TXT owner names whose synthetic answer is DNSSEC
	// authenticated. It is consumed by LookupTXTAuthenticated in tests.
	SecureTXT map[string]bool
	PTR       map[string][]string
	TLSA      map[string]TLSAResult

	// Queries counts lookups by type and name, so a test can assert that the
	// SPF lookup limit actually stopped the traversal.
	Queries []string
}

// NewStaticBackend returns an empty in-memory backend.
func NewStaticBackend() *StaticBackend {
	return &StaticBackend{
		Hosts:     map[string][]string{},
		MX:        map[string][]string{},
		TXT:       map[string][]string{},
		SecureTXT: map[string]bool{},
		PTR:       map[string][]string{},
		TLSA:      map[string]TLSAResult{},
	}
}

func (s *StaticBackend) record(kind, name string) {
	s.mu.Lock()
	s.Queries = append(s.Queries, kind+":"+strings.ToLower(name))
	s.mu.Unlock()
}

// QueryCount returns how many queries have been made.
func (s *StaticBackend) QueryCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Queries)
}

func (s *StaticBackend) lookup(table map[string][]string, name string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return table[strings.ToLower(strings.TrimSuffix(name, "."))], nil
}

func (s *StaticBackend) LookupHost(host string) ([]string, error) {
	s.record("host", host)
	return s.lookup(s.Hosts, host)
}

func (s *StaticBackend) LookupMX(domain string) ([]string, error) {
	s.record("mx", domain)
	return s.lookup(s.MX, domain)
}

func (s *StaticBackend) LookupTXT(name string) ([]string, error) {
	s.record("txt", name)
	return s.lookup(s.TXT, name)
}

func (s *StaticBackend) LookupPTR(ip string) ([]string, error) {
	s.record("ptr", ip)
	return s.lookup(s.PTR, ip)
}

// AddHost registers A/AAAA answers.
func (s *StaticBackend) AddHost(name string, addrs ...string) *StaticBackend {
	s.Hosts[strings.ToLower(name)] = addrs
	return s
}

// AddMX registers MX answers in preference order.
func (s *StaticBackend) AddMX(domain string, hosts ...string) *StaticBackend {
	s.MX[strings.ToLower(domain)] = hosts
	return s
}

// AddTXT registers TXT answers.
func (s *StaticBackend) AddTXT(name string, records ...string) *StaticBackend {
	s.TXT[strings.ToLower(name)] = records
	return s
}

// AddSecureTXT registers a TXT answer with the DNSSEC Authenticated Data bit.
func (s *StaticBackend) AddSecureTXT(name string, records ...string) *StaticBackend {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	s.TXT[name] = records
	s.SecureTXT[name] = true
	return s
}

// AddPTR registers reverse answers.
func (s *StaticBackend) AddPTR(ip string, names ...string) *StaticBackend {
	s.PTR[strings.ToLower(ip)] = names
	return s
}

// AddTLSA registers a TLSA answer for the given owner name.
func (s *StaticBackend) AddTLSA(name string, result TLSAResult) *StaticBackend {
	s.TLSA[strings.ToLower(name)] = result
	return s
}

// NewTestResolver returns a resolver backed by an in-memory zone, with
// caching disabled so each call is observable.
func NewTestResolver(backend *StaticBackend) *Resolver {
	r := NewResolver(WithBackend(backend))
	r.staticTLSA = backend
	// A zero TTL would be treated as "expire immediately"; use a short but
	// non-zero window and clear the cache between assertions instead.
	r.ttl = 0
	return r
}

var _ Backend = (*netBackend)(nil)
var _ Backend = (*StaticBackend)(nil)

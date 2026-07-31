// Package dnsx provides the caching DNS client shared by the rules engine and
// the authentication verifiers. It wraps the standard resolver for common
// record types and falls back to a raw DNS client for the record types the
// standard library cannot query, notably TLSA.
package dnsx

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// DefaultRBLs are the zones consulted by rbl_check when the caller does not
// name one. They are all query-only public zones; operators running at volume
// should configure their own via WithRBLs.
var DefaultRBLs = []string{
	"zen.spamhaus.org",
	"bl.spamcop.net",
	"b.barracudacentral.org",
}

// Resolver performs DNS lookups on behalf of rule scripts. It is safe for
// concurrent use and caches both positive and negative answers for a fixed
// TTL, because a mail gateway will otherwise re-query the same sender domain
// once per message.
//
// A nil *Resolver is valid and means "no network access": every lookup
// reports a miss so that rules degrade to header-only decisions rather than
// blocking. Callers opt in explicitly by constructing one.
type Resolver struct {
	timeout time.Duration
	ttl     time.Duration
	rbls    []string
	netres  *net.Resolver
	// rawServer is the host:port used for record types the standard resolver
	// cannot query. Empty means "read /etc/resolv.conf".
	rawServer string
	// queryBackend overrides the network backend; nil uses the system
	// resolver.
	queryBackend Backend
	// staticTLSA supplies TLSA answers in tests, bypassing the raw DNS path.
	staticTLSA *StaticBackend

	mu    sync.RWMutex
	cache map[string]cacheEntry

	// Lookups counts completed queries, for observability in the CLI.
	lookups int64
	hits    int64
}

type cacheEntry struct {
	value   interface{}
	expires time.Time
}

// ResolverOption configures a Resolver.
type ResolverOption func(*Resolver)

// WithTimeout sets the per-query timeout. The default is 3 seconds.
func WithTimeout(d time.Duration) ResolverOption {
	return func(r *Resolver) {
		if d > 0 {
			r.timeout = d
		}
	}
}

// WithCacheTTL sets how long answers are cached. The default is 5 minutes.
func WithCacheTTL(d time.Duration) ResolverOption {
	return func(r *Resolver) {
		if d > 0 {
			r.ttl = d
		}
	}
}

// WithRBLs replaces the default DNSBL zone list.
func WithRBLs(zones []string) ResolverOption {
	return func(r *Resolver) {
		if len(zones) > 0 {
			r.rbls = zones
		}
	}
}

// WithNameserver directs all queries at a specific DNS server, given as
// host:port. An empty string uses the system resolver.
func WithNameserver(addr string) ResolverOption {
	return func(r *Resolver) {
		if addr == "" {
			return
		}
		r.netres = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: r.timeout}
				return d.DialContext(ctx, network, addr)
			},
		}
	}
}

// NewResolver creates a caching resolver with sane defaults.
func NewResolver(opts ...ResolverOption) *Resolver {
	r := &Resolver{
		timeout: 3 * time.Second,
		ttl:     5 * time.Minute,
		rbls:    DefaultRBLs,
		netres:  net.DefaultResolver,
		cache:   make(map[string]cacheEntry),
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Enabled reports whether network lookups will actually be performed.
func (r *Resolver) Enabled() bool { return r != nil }

// Stats returns the number of upstream queries and cache hits so far.
func (r *Resolver) Stats() (lookups, hits int64) {
	if r == nil {
		return 0, 0
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.lookups, r.hits
}

func (r *Resolver) get(key string) (interface{}, bool) {
	r.mu.RLock()
	entry, ok := r.cache[key]
	r.mu.RUnlock()
	if !ok || time.Now().After(entry.expires) {
		return nil, false
	}
	r.mu.Lock()
	r.hits++
	r.mu.Unlock()
	return entry.value, true
}

func (r *Resolver) put(key string, value interface{}) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache[key] = cacheEntry{value: value, expires: time.Now().Add(r.ttl)}
	r.lookups++
}

func (r *Resolver) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), r.timeout)
}

// LookupHost resolves a hostname to its IP addresses.
func (r *Resolver) LookupHost(host string) []string {
	if r == nil || host == "" {
		return nil
	}
	key := "host:" + strings.ToLower(host)
	if v, ok := r.get(key); ok {
		return v.([]string)
	}
	addrs, err := r.backend().LookupHost(host)
	if err != nil {
		addrs = nil
	}
	sort.Strings(addrs)
	r.put(key, addrs)
	return addrs
}

// LookupMX returns the MX hosts for a domain, ordered by preference.
func (r *Resolver) LookupMX(domain string) []string {
	if r == nil || domain == "" {
		return nil
	}
	key := "mx:" + strings.ToLower(domain)
	if v, ok := r.get(key); ok {
		return v.([]string)
	}
	hosts, err := r.backend().LookupMX(domain)
	if err != nil {
		hosts = nil
	}
	r.put(key, hosts)
	return hosts
}

// LookupTXT returns the TXT records for a name.
func (r *Resolver) LookupTXT(name string) []string {
	if r == nil || name == "" {
		return nil
	}
	key := "txt:" + strings.ToLower(name)
	if v, ok := r.get(key); ok {
		return v.([]string)
	}
	records, err := r.backend().LookupTXT(name)
	if err != nil {
		records = nil
	}
	r.put(key, records)
	return records
}

// LookupPTR returns the reverse DNS names for an IP address.
func (r *Resolver) LookupPTR(ip string) []string {
	if r == nil || ip == "" {
		return nil
	}
	key := "ptr:" + ip
	if v, ok := r.get(key); ok {
		return v.([]string)
	}
	names, err := r.backend().LookupPTR(ip)
	if err != nil {
		names = nil
	}
	for i := range names {
		names[i] = strings.TrimSuffix(names[i], ".")
	}
	r.put(key, names)
	return names
}

// HasMX reports whether a domain publishes any MX record. Per RFC 5321 a
// domain with an A record but no MX is still mail-routable, so callers that
// want deliverability rather than strict MX presence should also check
// LookupHost.
func (r *Resolver) HasMX(domain string) bool {
	return len(r.LookupMX(domain)) > 0
}

// RBLResult is the outcome of a single DNSBL query.
type RBLResult struct {
	Zone    string
	Listed  bool
	Codes   []string
	Comment string
}

// CheckRBL queries one DNSBL zone for an IP address.
func (r *Resolver) CheckRBL(ip, zone string) RBLResult {
	result := RBLResult{Zone: zone}
	if r == nil || ip == "" || zone == "" {
		return result
	}

	query := reverseIPForDNSBL(ip)
	if query == "" {
		return result
	}
	name := query + "." + strings.TrimSuffix(zone, ".")

	key := "rbl:" + name
	if v, ok := r.get(key); ok {
		return v.(RBLResult)
	}

	addrs, err := r.backend().LookupHost(name)
	if err == nil && len(addrs) > 0 {
		result.Listed = true
		result.Codes = addrs
		if txt := r.LookupTXT(name); len(txt) > 0 {
			result.Comment = txt[0]
		}
	}
	r.put(key, result)
	return result
}

// CheckRBLs queries every configured zone and returns the first listing found
// along with the full set of results.
func (r *Resolver) CheckRBLs(ip string) (listed bool, results []RBLResult) {
	if r == nil {
		return false, nil
	}
	for _, zone := range r.rbls {
		res := r.CheckRBL(ip, zone)
		results = append(results, res)
		if res.Listed {
			listed = true
		}
	}
	return listed, results
}

// Zones returns the configured DNSBL zones.
func (r *Resolver) Zones() []string {
	if r == nil {
		return nil
	}
	return r.rbls
}

// reverseIPForDNSBL renders an IP in the nibble/octet-reversed form DNSBLs
// expect. It returns "" for input that is not an IP address.
func reverseIPForDNSBL(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return itoa(int(v4[3])) + "." + itoa(int(v4[2])) + "." + itoa(int(v4[1])) + "." + itoa(int(v4[0]))
	}
	v6 := parsed.To16()
	if v6 == nil {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	var sb strings.Builder
	for i := len(v6) - 1; i >= 0; i-- {
		sb.WriteByte(hexdigits[v6[i]&0x0f])
		sb.WriteByte('.')
		sb.WriteByte(hexdigits[v6[i]>>4])
		if i > 0 {
			sb.WriteByte('.')
		}
	}
	return sb.String()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [4]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TLSARecord is a DANE TLSA resource record (RFC 6698).
type TLSARecord struct {
	Usage        uint8  // 0 PKIX-TA, 1 PKIX-EE, 2 DANE-TA, 3 DANE-EE
	Selector     uint8  // 0 full certificate, 1 subject public key info
	MatchingType uint8  // 0 exact, 1 SHA-256, 2 SHA-512
	Certificate  string // hex-encoded association data
}

// TLSAResult is the outcome of a TLSA lookup.
type TLSAResult struct {
	Name    string
	Records []TLSARecord
	// Secure reports that the answer carried the DNSSEC Authenticated Data
	// bit from the configured validating resolver.
	//
	// DANE without DNSSEC is meaningless: an attacker who can forge the TLSA
	// answer can simply strip it. Callers must treat Secure == false as
	// "DANE not usable", not as "DANE absent".
	Secure bool
	// Found reports whether any TLSA record exists at the name.
	Found bool
	Error string
}

// TXTResult is a TXT lookup that preserves DNSSEC authentication state.
// Secure is only meaningful when the configured resolver is trusted to
// validate DNSSEC and the query path to it cannot be spoofed.
type TXTResult struct {
	Name    string
	Records []string
	Secure  bool
	Found   bool
	Error   string
}

// SetNameserverForRaw configures the server used for raw queries such as
// TLSA. It should be a DNSSEC-validating resolver, since the AD bit is only
// trustworthy over a secure channel to a validator.
func WithRawNameserver(addr string) ResolverOption {
	return func(r *Resolver) {
		r.rawServer = addr
	}
}

// systemNameserver returns the first nameserver from resolv.conf, used when
// no raw nameserver is configured explicitly.
func systemNameserver() string {
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err != nil || len(config.Servers) == 0 {
		return "1.1.1.1:53"
	}
	port := config.Port
	if port == "" {
		port = "53"
	}
	return net.JoinHostPort(config.Servers[0], port)
}

// LookupTLSA queries the TLSA records for a mail host and port, following the
// _port._proto.host naming convention of RFC 6698.
func (r *Resolver) LookupTLSA(host string, port int) TLSAResult {
	name := fmt.Sprintf("_%d._tcp.%s", port, strings.TrimSuffix(host, "."))
	result := TLSAResult{Name: name}
	if r == nil || host == "" {
		result.Error = "resolver disabled"
		return result
	}

	key := "tlsa:" + name
	if v, ok := r.get(key); ok {
		return v.(TLSAResult)
	}

	// Tests supply TLSA answers in memory rather than over the wire.
	if r.staticTLSA != nil {
		r.staticTLSA.record("tlsa", name)
		answer, ok := r.staticTLSA.TLSA[strings.ToLower(name)]
		if !ok {
			result.Error = ""
			return result
		}
		answer.Name = name
		return answer
	}

	server := r.rawServer
	if server == "" {
		server = systemNameserver()
	}

	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeTLSA)
	// Request DNSSEC records so the validating resolver reports the AD bit.
	query.SetEdns0(4096, true)
	query.AuthenticatedData = true

	client := &dns.Client{Timeout: r.timeout}
	response, _, err := client.Exchange(query, server)
	if err != nil {
		// Retry over TCP: TLSA answers with several records frequently
		// exceed the UDP payload and come back truncated.
		client.Net = "tcp"
		response, _, err = client.Exchange(query, server)
	}
	if err != nil {
		result.Error = err.Error()
		r.put(key, result)
		return result
	}
	if response.Truncated {
		client.Net = "tcp"
		if tcpResp, _, tcpErr := client.Exchange(query, server); tcpErr == nil {
			response = tcpResp
		}
	}

	result.Secure = response.AuthenticatedData
	for _, answer := range response.Answer {
		tlsa, ok := answer.(*dns.TLSA)
		if !ok {
			continue
		}
		result.Found = true
		result.Records = append(result.Records, TLSARecord{
			Usage:        tlsa.Usage,
			Selector:     tlsa.Selector,
			MatchingType: tlsa.MatchingType,
			Certificate:  strings.ToLower(tlsa.Certificate),
		})
	}

	r.put(key, result)
	return result
}

// LookupTXTAuthenticated queries TXT over the raw DNS path so callers can
// distinguish a DNSSEC-authenticated policy record from an ordinary answer.
func (r *Resolver) LookupTXTAuthenticated(name string) TXTResult {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	result := TXTResult{Name: name}
	if r == nil || name == "" {
		result.Error = "resolver disabled"
		return result
	}

	key := "txt-auth:" + strings.ToLower(name)
	if v, ok := r.get(key); ok {
		return v.(TXTResult)
	}

	if r.staticTLSA != nil {
		r.staticTLSA.record("txt-auth", name)
		lookupName := strings.ToLower(name)
		result.Records = append([]string(nil), r.staticTLSA.TXT[lookupName]...)
		result.Found = len(result.Records) > 0
		result.Secure = result.Found && r.staticTLSA.SecureTXT[lookupName]
		r.put(key, result)
		return result
	}

	server := r.rawServer
	if server == "" {
		server = systemNameserver()
	}
	query := new(dns.Msg)
	query.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	query.SetEdns0(4096, true)
	query.AuthenticatedData = true

	client := &dns.Client{Timeout: r.timeout}
	response, _, err := client.Exchange(query, server)
	if err == nil && response.Truncated {
		client.Net = "tcp"
		response, _, err = client.Exchange(query, server)
	}
	if err != nil {
		result.Error = err.Error()
		r.put(key, result)
		return result
	}
	result.Secure = response.AuthenticatedData
	for _, answer := range response.Answer {
		txt, ok := answer.(*dns.TXT)
		if !ok {
			continue
		}
		result.Found = true
		result.Records = append(result.Records, strings.Join(txt.Txt, ""))
	}
	r.put(key, result)
	return result
}

// IsPrivateIP reports whether an address is in a private, loopback, or
// link-local range. Such an address appearing as the origin of an external
// message is a forged-Received signal.
func IsPrivateIP(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	return parsed.IsLoopback() ||
		parsed.IsPrivate() ||
		parsed.IsLinkLocalUnicast() ||
		parsed.IsLinkLocalMulticast() ||
		parsed.IsUnspecified()
}

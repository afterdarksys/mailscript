// Package authverify performs real cryptographic and policy verification of
// SPF, DKIM, DMARC and DANE.
//
// Threats: this package defends against sender-identity forgery. Spammers and
// phishers routinely inject a forged Authentication-Results header claiming
// "spf=pass; dkim=pass; dmarc=pass"; any filter that reads that header
// without knowing which MTA wrote it is trivially bypassed. Everything here
// re-derives the verdict from the message bytes and DNS, so the result does
// not depend on anything the sender controls.
//
// It does NOT defend against: a compromised signing key, a hostile
// DNSSEC-unvalidated resolver path (see the DANE caveats), replay of an
// intact and still-valid signed message, or content that is malicious while
// being correctly authenticated. Authentication proves provenance, not
// benignity.
package authverify

import (
	"fmt"
	"net"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

// SPF result values defined by RFC 7208 section 2.6.
const (
	SPFNone      = "none"
	SPFNeutral   = "neutral"
	SPFPass      = "pass"
	SPFFail      = "fail"
	SPFSoftfail  = "softfail"
	SPFTempError = "temperror"
	SPFPermError = "permerror"
)

// RFC 7208 section 4.6.4 processing limits. These are not tuning knobs: they
// are the mechanism that stops a hostile SPF record from turning one inbound
// message into an unbounded DNS amplification against third parties.
const (
	maxSPFLookups     = 10 // terms that cause a DNS query
	maxSPFVoidLookups = 2  // queries returning NXDOMAIN or no records
	maxSPFRedirects   = 10 // guards against a redirect cycle
	maxSPFRecordSize  = 4096
)

// SPFResult is the outcome of an SPF evaluation.
type SPFResult struct {
	Result string
	// Domain is the identity that was checked (the MAIL FROM domain, or the
	// HELO name when MAIL FROM is empty).
	Domain string
	// Sender is the full identity string that was evaluated.
	Sender string
	// ClientIP is the address the evaluation was performed against.
	ClientIP string
	// Mechanism names the term that produced the result, if any.
	Mechanism string
	// Explanation carries the reason for a fail, or the error detail.
	Explanation string
	// Record is the SPF record that was evaluated.
	Record string
	// Lookups counts the DNS-querying terms consumed.
	Lookups int
}

// spfEvaluator carries the per-evaluation limit counters.
type spfEvaluator struct {
	resolver *dnsx.Resolver
	ip       net.IP
	ipIsV4   bool
	sender   string
	helo     string

	lookups     int
	voidLookups int
	redirects   int
}

// VerifySPF evaluates SPF for a connecting client, per RFC 7208.
//
// mailFrom is the envelope sender; an empty value (a bounce) causes the HELO
// identity to be checked instead, as section 2.4 requires.
func VerifySPF(resolver *dnsx.Resolver, clientIP, mailFrom, helo string) SPFResult {
	result := SPFResult{ClientIP: clientIP, Sender: mailFrom}

	if !resolver.Enabled() {
		result.Result = SPFTempError
		result.Explanation = "no DNS resolver configured"
		return result
	}

	ip := net.ParseIP(clientIP)
	if ip == nil {
		result.Result = SPFPermError
		result.Explanation = fmt.Sprintf("client address %q is not an IP", clientIP)
		return result
	}

	// RFC 7208 section 2.4: with a null reverse path, check the HELO identity.
	identity := mailFrom
	if strings.TrimSpace(identity) == "" {
		identity = "postmaster@" + strings.TrimSpace(helo)
		result.Sender = identity
	}

	domain := identity
	if at := strings.LastIndex(identity, "@"); at >= 0 {
		domain = identity[at+1:]
	}
	domain = strings.ToLower(strings.Trim(strings.TrimSpace(domain), "[]"))
	result.Domain = domain

	if domain == "" || !strings.Contains(domain, ".") {
		result.Result = SPFNone
		// Distinguish "nothing to check" from "checked and found nothing":
		// SPF authenticates the envelope, not the From header, so without an
		// envelope sender or a HELO name there is no identity to evaluate.
		if strings.TrimSpace(mailFrom) == "" && strings.TrimSpace(helo) == "" {
			result.Explanation = "no envelope sender or HELO name supplied; " +
				"SPF authenticates the SMTP envelope, not the From header"
		} else {
			result.Explanation = fmt.Sprintf("sender identity %q has no usable domain", identity)
		}
		return result
	}

	evaluator := &spfEvaluator{
		resolver: resolver,
		ip:       ip,
		ipIsV4:   ip.To4() != nil,
		sender:   identity,
		helo:     helo,
	}

	verdict, mechanism, record, err := evaluator.check(domain)
	result.Result = verdict
	result.Mechanism = mechanism
	result.Record = record
	result.Lookups = evaluator.lookups
	if err != nil {
		result.Explanation = err.Error()
	}
	return result
}

// check evaluates the SPF record for one domain.
func (e *spfEvaluator) check(domain string) (result, mechanism, record string, err error) {
	spfRecord, findErr := e.findRecord(domain)
	if findErr != nil {
		return findErr.result, "", "", findErr
	}

	terms := strings.Fields(spfRecord)
	if len(terms) == 0 || !strings.EqualFold(terms[0], "v=spf1") {
		return SPFPermError, "", spfRecord, fmt.Errorf("record does not start with v=spf1")
	}

	var redirect string

	for _, term := range terms[1:] {
		if term == "" {
			continue
		}

		// Modifiers are name=value; mechanisms are [qualifier]name[:value].
		if eq := strings.Index(term, "="); eq > 0 && !strings.ContainsAny(term[:eq], ":/") {
			name := strings.ToLower(term[:eq])
			value := term[eq+1:]
			switch name {
			case "redirect":
				redirect = value
			case "exp":
				// Explanation strings are cosmetic; skip them rather than
				// spending a DNS lookup on an attacker-controlled name.
			}
			continue
		}

		qualifier := byte('+')
		body := term
		switch term[0] {
		case '+', '-', '~', '?':
			qualifier = term[0]
			body = term[1:]
		}

		name, value := body, ""
		if colon := strings.Index(body, ":"); colon >= 0 {
			name, value = body[:colon], body[colon+1:]
		} else if slash := strings.Index(body, "/"); slash >= 0 {
			name, value = body[:slash], body[slash:]
		}
		name = strings.ToLower(name)

		matched, matchErr := e.evaluateMechanism(name, value, body, domain)
		if matchErr != nil {
			return matchErr.result, body, spfRecord, matchErr
		}
		if matched {
			return qualifierToResult(qualifier), body, spfRecord, nil
		}
	}

	if redirect != "" {
		e.redirects++
		if e.redirects > maxSPFRedirects {
			return SPFPermError, "redirect", spfRecord, fmt.Errorf("redirect chain exceeded %d hops", maxSPFRedirects)
		}
		if err := e.spend(); err != nil {
			return SPFPermError, "redirect", spfRecord, err
		}
		// RFC 7208 section 6.1: a redirect to a domain with no record is a
		// permerror, not a none.
		verdict, mech, rec, rerr := e.check(strings.ToLower(redirect))
		if verdict == SPFNone {
			return SPFPermError, "redirect", rec, fmt.Errorf("redirect target %q has no SPF record", redirect)
		}
		return verdict, mech, rec, rerr
	}

	// No mechanism matched and no "all" term was present.
	return SPFNeutral, "", spfRecord, nil
}

// spfError couples an error with the SPF result it should produce.
type spfError struct {
	result string
	msg    string
}

func (e *spfError) Error() string { return e.msg }

// spend accounts for one DNS-querying term against the lookup budget.
func (e *spfEvaluator) spend() *spfError {
	e.lookups++
	if e.lookups > maxSPFLookups {
		return &spfError{SPFPermError, fmt.Sprintf("exceeded the %d DNS-lookup limit", maxSPFLookups)}
	}
	return nil
}

func (e *spfEvaluator) countVoid() *spfError {
	e.voidLookups++
	if e.voidLookups > maxSPFVoidLookups {
		return &spfError{SPFPermError, fmt.Sprintf("exceeded the %d void-lookup limit", maxSPFVoidLookups)}
	}
	return nil
}

// findRecord fetches and validates the single SPF record for a domain.
func (e *spfEvaluator) findRecord(domain string) (string, *spfError) {
	records := e.resolver.LookupTXT(domain)

	var found []string
	for _, record := range records {
		if len(record) > maxSPFRecordSize {
			return "", &spfError{SPFPermError, "SPF record exceeds the size limit"}
		}
		if strings.HasPrefix(strings.ToLower(record), "v=spf1") {
			found = append(found, record)
		}
	}

	switch len(found) {
	case 0:
		if err := e.countVoid(); err != nil {
			return "", err
		}
		return "", &spfError{SPFNone, fmt.Sprintf("no SPF record published for %q", domain)}
	case 1:
		return found[0], nil
	default:
		// RFC 7208 section 4.5: multiple records are a permerror, because
		// which one applies is undefined and an attacker could exploit the
		// disagreement between implementations.
		return "", &spfError{SPFPermError, fmt.Sprintf("%d SPF records published for %q", len(found), domain)}
	}
}

// evaluateMechanism evaluates one SPF mechanism against the client address.
func (e *spfEvaluator) evaluateMechanism(name, value, body, domain string) (bool, *spfError) {
	switch name {
	case "all":
		return true, nil

	case "ip4", "ip6":
		return e.matchIPMechanism(name, value)

	case "a":
		if err := e.spend(); err != nil {
			return false, err
		}
		target, v4Len, v6Len := e.mechanismTarget(value, domain)
		addrs := e.resolver.LookupHost(target)
		if len(addrs) == 0 {
			if err := e.countVoid(); err != nil {
				return false, err
			}
		}
		return e.anyAddressMatches(addrs, v4Len, v6Len), nil

	case "mx":
		if err := e.spend(); err != nil {
			return false, err
		}
		target, v4Len, v6Len := e.mechanismTarget(value, domain)
		hosts := e.resolver.LookupMX(target)
		if len(hosts) == 0 {
			if err := e.countVoid(); err != nil {
				return false, err
			}
		}
		// RFC 7208 section 4.6.4 caps the MX mechanism at 10 hosts.
		if len(hosts) > 10 {
			return false, &spfError{SPFPermError, "mx mechanism resolved more than 10 hosts"}
		}
		for _, host := range hosts {
			if e.anyAddressMatches(e.resolver.LookupHost(host), v4Len, v6Len) {
				return true, nil
			}
		}
		return false, nil

	case "include":
		if err := e.spend(); err != nil {
			return false, err
		}
		target := strings.ToLower(strings.TrimSpace(value))
		if target == "" {
			return false, &spfError{SPFPermError, "include mechanism has no domain"}
		}
		verdict, _, _, nestedErr := e.check(target)
		switch verdict {
		case SPFPass:
			return true, nil
		case SPFTempError:
			return false, &spfError{SPFTempError, fmt.Sprintf("include:%s returned temperror", target)}
		case SPFNone:
			// Section 5.2: an include of a domain with no record is a
			// permerror for the including record.
			return false, &spfError{SPFPermError, fmt.Sprintf("include:%s has no usable SPF record", target)}
		case SPFPermError:
			// Propagate the nested reason. Collapsing it into a generic
			// message would hide a lookup-limit breach, which is exactly the
			// condition an operator needs to see.
			msg := fmt.Sprintf("include:%s returned permerror", target)
			if nestedErr != nil {
				msg = fmt.Sprintf("include:%s: %v", target, nestedErr)
			}
			return false, &spfError{SPFPermError, msg}
		default:
			return false, nil
		}

	case "exists":
		if err := e.spend(); err != nil {
			return false, err
		}
		target := strings.ToLower(strings.TrimSpace(value))
		if target == "" {
			return false, &spfError{SPFPermError, "exists mechanism has no domain"}
		}
		addrs := e.resolver.LookupHost(target)
		if len(addrs) == 0 {
			if err := e.countVoid(); err != nil {
				return false, err
			}
		}
		return len(addrs) > 0, nil

	case "ptr":
		// RFC 7208 section 5.5 deprecates ptr and warns it is slow and
		// unreliable. It is evaluated for compatibility but still costs a
		// lookup against the budget.
		if err := e.spend(); err != nil {
			return false, err
		}
		target := strings.ToLower(strings.TrimSpace(value))
		if target == "" {
			target = domain
		}
		for _, name := range e.resolver.LookupPTR(e.ip.String()) {
			name = strings.TrimSuffix(strings.ToLower(name), ".")
			if name != target && !strings.HasSuffix(name, "."+target) {
				continue
			}
			// Forward-confirm, as the specification requires.
			for _, addr := range e.resolver.LookupHost(name) {
				if ipEqual(addr, e.ip) {
					return true, nil
				}
			}
		}
		return false, nil

	default:
		return false, &spfError{SPFPermError, fmt.Sprintf("unknown SPF mechanism %q", body)}
	}
}

// matchIPMechanism evaluates ip4 and ip6 terms.
func (e *spfEvaluator) matchIPMechanism(name, value string) (bool, *spfError) {
	if value == "" {
		return false, &spfError{SPFPermError, fmt.Sprintf("%s mechanism has no address", name)}
	}

	wantV4 := name == "ip4"
	if wantV4 != e.ipIsV4 {
		return false, nil // address families differ; cannot match
	}

	if strings.Contains(value, "/") {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			return false, &spfError{SPFPermError, fmt.Sprintf("%s:%s is not a valid CIDR", name, value)}
		}
		return network.Contains(e.ip), nil
	}

	addr := net.ParseIP(value)
	if addr == nil {
		return false, &spfError{SPFPermError, fmt.Sprintf("%s:%s is not a valid address", name, value)}
	}
	return addr.Equal(e.ip), nil
}

// mechanismTarget splits an a/mx mechanism argument into its domain and
// optional CIDR prefix lengths.
func (e *spfEvaluator) mechanismTarget(value, domain string) (target string, v4Len, v6Len int) {
	v4Len, v6Len = 32, 128
	target = domain

	if value == "" {
		return target, v4Len, v6Len
	}

	// The form is [domain][/v4len][//v6len].
	rest := value
	if i := strings.Index(rest, "//"); i >= 0 {
		fmt.Sscanf(rest[i+2:], "%d", &v6Len)
		rest = rest[:i]
	}
	if i := strings.Index(rest, "/"); i >= 0 {
		fmt.Sscanf(rest[i+1:], "%d", &v4Len)
		rest = rest[:i]
	}
	if strings.TrimSpace(rest) != "" {
		target = strings.ToLower(strings.TrimSpace(rest))
	}

	if v4Len < 0 || v4Len > 32 {
		v4Len = 32
	}
	if v6Len < 0 || v6Len > 128 {
		v6Len = 128
	}
	return target, v4Len, v6Len
}

// anyAddressMatches reports whether the client address falls inside any of
// the given addresses, widened to the mechanism's prefix length.
func (e *spfEvaluator) anyAddressMatches(addrs []string, v4Len, v6Len int) bool {
	for _, addr := range addrs {
		parsed := net.ParseIP(addr)
		if parsed == nil {
			continue
		}

		isV4 := parsed.To4() != nil
		if isV4 != e.ipIsV4 {
			continue
		}

		bits, length := 128, v6Len
		if isV4 {
			bits, length = 32, v4Len
		}
		mask := net.CIDRMask(length, bits)
		if mask == nil {
			continue
		}

		network := &net.IPNet{IP: parsed.Mask(mask), Mask: mask}
		if network.Contains(e.ip) {
			return true
		}
	}
	return false
}

func ipEqual(addr string, ip net.IP) bool {
	parsed := net.ParseIP(addr)
	return parsed != nil && parsed.Equal(ip)
}

func qualifierToResult(qualifier byte) string {
	switch qualifier {
	case '-':
		return SPFFail
	case '~':
		return SPFSoftfail
	case '?':
		return SPFNeutral
	default:
		return SPFPass
	}
}

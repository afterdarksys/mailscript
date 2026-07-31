package authverify

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

// DANE result values.
const (
	DANENone      = "none"      // no TLSA records published
	DANEAvailable = "available" // validated TLSA records found; no certificate checked
	DANEPass      = "pass"      // a presented certificate matched a TLSA record
	DANEFail      = "fail"      // TLSA records exist but nothing matched
	DANEInsecure  = "insecure"  // TLSA records exist but the DNSSEC chain was not validated
	DANETempError = "temperror" // lookup failed
	DANEPermError = "permerror" // records are malformed
)

// TLSA certificate usage values (RFC 6698 section 2.1.1). Only DANE-TA and
// DANE-EE are meaningful for SMTP; RFC 7672 section 3.1.3 requires receivers
// to ignore PKIX-TA and PKIX-EE for opportunistic DANE.
const (
	UsagePKIXTA = 0
	UsagePKIXEE = 1
	UsageDANETA = 2
	UsageDANEEE = 3
)

// DANEResult is the outcome of a DANE evaluation for one mail host.
type DANEResult struct {
	Result string
	// Host is the MX hostname that was checked.
	Host string
	Port int
	// TLSAFound reports whether any TLSA record exists.
	TLSAFound bool
	// DNSSECValidated reports that the TLSA answer carried the Authenticated
	// Data bit. Without it the records are unusable: an attacker who can
	// forge the answer can also strip it, so unvalidated TLSA data provides
	// no security at all.
	DNSSECValidated bool
	// Records lists the published associations.
	Records []dnsx.TLSARecord
	// UsableRecords counts records with a usage SMTP DANE accepts.
	UsableRecords int
	// MatchedRecord indexes the record a presented certificate matched.
	MatchedRecord int
	Explanation   string
}

// DANEDomainResult aggregates DANE across every MX host of a domain.
type DANEDomainResult struct {
	Result string
	Domain string
	Hosts  []DANEResult
	// SecureHosts counts MX hosts publishing DNSSEC-validated TLSA records.
	SecureHosts int
	Explanation string
}

// CheckDANE looks up the TLSA records for one mail host.
//
// This is discovery only: it reports whether the host commits to DANE and
// whether that commitment is DNSSEC-protected. Proving the host honours the
// commitment additionally requires the certificate it presents during a TLS
// handshake, which VerifyDANECertificate checks.
func CheckDANE(resolver *dnsx.Resolver, host string, port int) DANEResult {
	result := DANEResult{Host: host, Port: port, MatchedRecord: -1}

	if !resolver.Enabled() {
		result.Result = DANETempError
		result.Explanation = "no DNS resolver configured"
		return result
	}
	if port <= 0 {
		port = 25
		result.Port = port
	}

	lookup := resolver.LookupTLSA(host, port)
	result.DNSSECValidated = lookup.Secure
	result.TLSAFound = lookup.Found
	result.Records = lookup.Records

	if lookup.Error != "" {
		result.Result = DANETempError
		result.Explanation = fmt.Sprintf("TLSA lookup for %s failed: %s", lookup.Name, lookup.Error)
		return result
	}
	if !lookup.Found {
		result.Result = DANENone
		result.Explanation = fmt.Sprintf("no TLSA records published at %s", lookup.Name)
		return result
	}

	for _, record := range lookup.Records {
		if record.Usage == UsageDANETA || record.Usage == UsageDANEEE {
			result.UsableRecords++
		}
	}

	if !lookup.Secure {
		// Fail closed on the security question: report the records but make
		// clear they cannot be relied on.
		result.Result = DANEInsecure
		result.Explanation = fmt.Sprintf(
			"%d TLSA record(s) at %s, but the answer was not DNSSEC-validated; "+
				"point --dns-server at a validating resolver to use DANE",
			len(lookup.Records), lookup.Name)
		return result
	}

	if result.UsableRecords == 0 {
		result.Result = DANEPermError
		result.Explanation = fmt.Sprintf(
			"%d TLSA record(s) published but none use DANE-TA or DANE-EE, which RFC 7672 requires for SMTP",
			len(lookup.Records))
		return result
	}

	result.Result = DANEAvailable
	result.Explanation = fmt.Sprintf(
		"%d usable DNSSEC-validated TLSA record(s) at %s", result.UsableRecords, lookup.Name)
	return result
}

// CheckDANEDomain evaluates DANE across every MX host of a domain, which is
// what determines whether mail to that domain can be delivered with
// authenticated TLS.
func CheckDANEDomain(resolver *dnsx.Resolver, domain string) DANEDomainResult {
	result := DANEDomainResult{Domain: domain}

	if !resolver.Enabled() {
		result.Result = DANETempError
		result.Explanation = "no DNS resolver configured"
		return result
	}

	hosts := resolver.LookupMX(domain)
	if len(hosts) == 0 {
		result.Result = DANENone
		result.Explanation = fmt.Sprintf("no MX records for %q", domain)
		return result
	}

	insecureHosts, tempErrors, permErrors := 0, 0, 0
	for _, host := range hosts {
		hostResult := CheckDANE(resolver, host, 25)
		result.Hosts = append(result.Hosts, hostResult)
		if hostResult.Result == DANEAvailable {
			result.SecureHosts++
		}
		switch hostResult.Result {
		case DANEInsecure:
			insecureHosts++
		case DANETempError:
			tempErrors++
		case DANEPermError:
			permErrors++
		}
	}

	switch {
	case result.SecureHosts == len(hosts):
		result.Result = DANEAvailable
		result.Explanation = fmt.Sprintf("all %d MX host(s) publish validated TLSA records", len(hosts))
	case result.SecureHosts > 0:
		// Partial deployment is a downgrade opportunity: an attacker steers
		// delivery to the MX without TLSA.
		result.Result = DANEInsecure
		result.Explanation = fmt.Sprintf(
			"only %d of %d MX host(s) publish validated TLSA records, so delivery can be downgraded",
			result.SecureHosts, len(hosts))
	case insecureHosts > 0:
		result.Result = DANEInsecure
		result.Explanation = fmt.Sprintf("%d MX host(s) publish TLSA records that were not DNSSEC-validated", insecureHosts)
	case tempErrors > 0:
		result.Result = DANETempError
		result.Explanation = fmt.Sprintf("TLSA lookup failed for %d of %d MX host(s)", tempErrors, len(hosts))
	case permErrors > 0:
		result.Result = DANEPermError
		result.Explanation = fmt.Sprintf("%d MX host(s) publish unusable TLSA records", permErrors)
	default:
		result.Result = DANENone
		result.Explanation = fmt.Sprintf("none of the %d MX host(s) publish usable TLSA records", len(hosts))
	}

	return result
}

// VerifyDANECertificate checks a presented certificate chain against the
// TLSA records for a host. It is used when MailScript itself made the TLS
// connection, for example when relaying to an upstream.
//
// chain must be the peer certificates in the order the server sent them,
// leaf first.
func VerifyDANECertificate(resolver *dnsx.Resolver, host string, port int, chain []*x509.Certificate) DANEResult {
	result := CheckDANE(resolver, host, port)
	if result.Result != DANEAvailable {
		return result
	}
	if len(chain) == 0 {
		result.Result = DANEFail
		result.Explanation = "no certificate was presented to match against the TLSA records"
		return result
	}

	for i, record := range result.Records {
		var candidates []*x509.Certificate
		switch record.Usage {
		case UsageDANEEE:
			// The end-entity certificate must match exactly.
			candidates = chain[:1]
		case UsageDANETA:
			// A trust anchor anywhere in the presented chain.
			candidates = chain
		default:
			continue // PKIX usages are not applicable to SMTP DANE
		}

		for _, cert := range candidates {
			association, err := selectAssociationData(cert, record.Selector)
			if err != nil {
				continue
			}
			digest, err := applyMatchingType(association, record.MatchingType)
			if err != nil {
				continue
			}

			expected, err := hex.DecodeString(record.Certificate)
			if err != nil {
				continue
			}
			// Constant-time: never compare certificate digests with a
			// variable-time equality check.
			if subtle.ConstantTimeCompare(digest, expected) == 1 {
				result.Result = DANEPass
				result.MatchedRecord = i
				result.Explanation = fmt.Sprintf(
					"certificate matched TLSA record %d (usage %d, selector %d, matching %d)",
					i, record.Usage, record.Selector, record.MatchingType)
				return result
			}
		}
	}

	result.Result = DANEFail
	result.MatchedRecord = -1
	result.Explanation = fmt.Sprintf(
		"presented certificate matched none of the %d usable TLSA record(s)", result.UsableRecords)
	return result
}

// selectAssociationData returns the bytes a TLSA selector refers to.
func selectAssociationData(cert *x509.Certificate, selector uint8) ([]byte, error) {
	switch selector {
	case 0: // full certificate
		return cert.Raw, nil
	case 1: // SubjectPublicKeyInfo
		return cert.RawSubjectPublicKeyInfo, nil
	default:
		return nil, fmt.Errorf("unknown TLSA selector %d", selector)
	}
}

// applyMatchingType hashes association data per the TLSA matching type.
func applyMatchingType(data []byte, matchingType uint8) ([]byte, error) {
	switch matchingType {
	case 0: // exact match on the raw data
		return data, nil
	case 1:
		sum := sha256.Sum256(data)
		return sum[:], nil
	case 2:
		sum := sha512.Sum512(data)
		return sum[:], nil
	default:
		return nil, fmt.Errorf("unknown TLSA matching type %d", matchingType)
	}
}

// DescribeTLSA renders a TLSA record in the conventional presentation form.
func DescribeTLSA(record dnsx.TLSARecord) string {
	usage := map[uint8]string{
		UsagePKIXTA: "PKIX-TA", UsagePKIXEE: "PKIX-EE",
		UsageDANETA: "DANE-TA", UsageDANEEE: "DANE-EE",
	}[record.Usage]
	if usage == "" {
		usage = fmt.Sprintf("usage%d", record.Usage)
	}

	selector := map[uint8]string{0: "Cert", 1: "SPKI"}[record.Selector]
	if selector == "" {
		selector = fmt.Sprintf("selector%d", record.Selector)
	}

	matching := map[uint8]string{0: "Full", 1: "SHA-256", 2: "SHA-512"}[record.MatchingType]
	if matching == "" {
		matching = fmt.Sprintf("matching%d", record.MatchingType)
	}

	digest := record.Certificate
	if len(digest) > 16 {
		digest = digest[:16] + "..."
	}
	return fmt.Sprintf("%s %s %s %s", usage, selector, matching, strings.ToLower(digest))
}

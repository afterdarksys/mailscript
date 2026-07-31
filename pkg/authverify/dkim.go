package authverify

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"hash"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

// DKIM result values, matching the RFC 8601 vocabulary.
const (
	DKIMNone      = "none"
	DKIMPass      = "pass"
	DKIMFail      = "fail"
	DKIMPolicy    = "policy"
	DKIMNeutral   = "neutral"
	DKIMTempError = "temperror"
	DKIMPermError = "permerror"
)

// Verification limits. These bound the work an attacker can induce with a
// crafted message and reject key sizes that no longer provide security.
const (
	// RFC 8301 sets 1024 bits as the floor for RSA signing keys and
	// recommends 2048. Anything smaller is treated as no signature at all.
	minRSAKeyBits = 1024
	// A message may carry many signatures; verify a bounded number so a
	// thousand-signature message cannot consume unbounded CPU and DNS.
	maxSignatures = 10
	// Reject absurd public keys before handing them to the parser.
	maxPublicKeyBytes = 8192
)

// DKIMSignatureResult is the verification outcome for one DKIM-Signature.
type DKIMSignatureResult struct {
	Result string
	// Domain is the d= tag: the identity claiming responsibility.
	Domain string
	// Selector is the s= tag.
	Selector string
	// Identity is the i= tag, the agent or user identifier.
	Identity string
	// Algorithm is the a= tag, for example "rsa-sha256".
	Algorithm string
	// HeadersSigned lists the fields covered by the signature.
	HeadersSigned []string
	// KeyBits is the size of the RSA key, or 256 for Ed25519.
	KeyBits int
	// Explanation describes why verification produced this result.
	Explanation string

	// BodyTruncated reports that the signature used an l= body-length tag
	// covering less than the whole body. Everything past that offset is
	// unsigned and can be replaced by an attacker while the signature still
	// verifies, so a pass with this flag set must not be treated as
	// authenticating the visible content.
	BodyTruncated bool
	// SignedBytes is the number of body bytes the signature covered.
	SignedBytes int
	// BodyBytes is the total size of the canonicalised body.
	BodyBytes int

	// Expired reports that the x= tag is in the past.
	Expired bool
	// TimestampFuture reports that the t= tag is implausibly far ahead.
	TimestampFuture bool
}

// DKIMResult aggregates every signature on a message.
type DKIMResult struct {
	// Result is the strongest single outcome: pass if any signature passed.
	Result string
	// Signatures holds the per-signature detail, in header order.
	Signatures []DKIMSignatureResult
	// PassingDomains lists the d= values of signatures that verified.
	PassingDomains []string
}

// VerifyDKIM verifies every DKIM-Signature on a message.
//
// headers must be the message's fields in received order, with values exactly
// as they appeared on the wire. body must be the raw body bytes after the
// blank separator line.
func VerifyDKIM(resolver *dnsx.Resolver, headers [][2]string, body []byte, now time.Time) DKIMResult {
	result := DKIMResult{Result: DKIMNone}

	if now.IsZero() {
		now = time.Now()
	}

	// Collect signature fields with their index so each can be excluded from
	// its own hash computation.
	var sigIndices []int
	for i, h := range headers {
		if strings.EqualFold(strings.TrimSpace(h[0]), "DKIM-Signature") {
			sigIndices = append(sigIndices, i)
		}
	}
	if len(sigIndices) == 0 {
		return result
	}
	if len(sigIndices) > maxSignatures {
		sigIndices = sigIndices[:maxSignatures]
	}

	if !resolver.Enabled() {
		result.Result = DKIMTempError
		result.Signatures = []DKIMSignatureResult{{
			Result:      DKIMTempError,
			Explanation: "no DNS resolver configured; the public key cannot be retrieved",
		}}
		return result
	}

	// A message carrying two From fields must never be reported as
	// DKIM-authenticated, even when a signature verifies.
	//
	// Canonicalisation consumes header instances bottom-up, so an attacker
	// who prepends a second From leaves the originally signed one in place
	// and the signature still verifies. The MUA, meanwhile, typically
	// displays the *first* From. The signature would then vouch for an
	// identity the recipient never sees. RFC 5322 permits exactly one From,
	// so the correct response is to reject the message rather than to
	// authenticate it.
	//
	// Signers defend against the same attack by oversigning (listing "from"
	// twice in h=), but a verifier cannot rely on every signer doing so.
	if n := countHeader(headers, "From"); n > 1 {
		result.Result = DKIMPermError
		result.Signatures = []DKIMSignatureResult{{
			Result: DKIMPermError,
			Explanation: fmt.Sprintf(
				"message carries %d From fields; RFC 5322 allows one, and the signed copy "+
					"need not be the one displayed", n),
		}}
		return result
	}

	for _, idx := range sigIndices {
		sig := verifyOneDKIM(resolver, headers, idx, body, now)
		result.Signatures = append(result.Signatures, sig)
		if sig.Result == DKIMPass {
			result.PassingDomains = append(result.PassingDomains, sig.Domain)
		}
	}

	// Any verified signature makes the message DKIM-authenticated; the
	// remaining failures are informational. This is what RFC 6376 section
	// 6.1 prescribes, and it is why a broken forwarder signature does not
	// invalidate the originator's.
	result.Result = DKIMFail
	for _, sig := range result.Signatures {
		if sig.Result == DKIMPass {
			result.Result = DKIMPass
			break
		}
	}
	if len(result.PassingDomains) == 0 {
		// Preserve a more specific failure mode when there is only one.
		if len(result.Signatures) == 1 {
			result.Result = result.Signatures[0].Result
		}
	}

	return result
}

// verifyOneDKIM verifies the signature at headers[sigIndex].
func verifyOneDKIM(resolver *dnsx.Resolver, headers [][2]string, sigIndex int, body []byte, now time.Time) DKIMSignatureResult {
	return verifyOneMessageSignature(resolver, headers, sigIndex, body, now, "DKIM-Signature", true)
}

// verifyOneMessageSignature implements the common DKIM/ARC-Message-Signature
// grammar. ARC omits DKIM's v= tag and signs its own field name.
func verifyOneMessageSignature(resolver *dnsx.Resolver, headers [][2]string, sigIndex int, body []byte, now time.Time, fieldName string, requireVersion bool) DKIMSignatureResult {
	out := DKIMSignatureResult{Result: DKIMPermError}

	rawSig := headers[sigIndex][1]
	tags, tagErr := parseStrictDKIMTags(rawSig)
	if tagErr != nil {
		out.Explanation = tagErr.Error()
		return out
	}

	// -- Required tags (RFC 6376 section 3.5) -------------------------------

	if version := tags["v"]; requireVersion && version != "1" {
		out.Explanation = fmt.Sprintf("unsupported DKIM version %q", version)
		return out
	}

	out.Domain = strings.ToLower(strings.TrimSpace(tags["d"]))
	out.Selector = strings.TrimSpace(tags["s"])
	out.Identity = tags["i"]
	out.Algorithm = strings.ToLower(strings.TrimSpace(tags["a"]))

	if out.Domain == "" || out.Selector == "" {
		out.Explanation = "signature is missing the d= or s= tag"
		return out
	}

	signatureB64 := stripWhitespace(tags["b"])
	bodyHashB64 := stripWhitespace(tags["bh"])
	if signatureB64 == "" || bodyHashB64 == "" {
		out.Explanation = "signature is missing the b= or bh= tag"
		return out
	}

	signedHeaderNames := splitHeaderList(tags["h"])
	if len(signedHeaderNames) == 0 {
		out.Explanation = "signature has an empty h= tag"
		return out
	}
	out.HeadersSigned = signedHeaderNames

	// RFC 6376 section 5.4 requires From to be signed. Without it the
	// signature says nothing about who the message claims to be from, which
	// is the only thing a filter cares about.
	if !containsFold(signedHeaderNames, "from") {
		out.Explanation = "the From field is not covered by the signature"
		return out
	}

	// -- Algorithm allowlist ------------------------------------------------

	var newHash func() hash.Hash
	var cryptoHash crypto.Hash
	var keyType string

	switch out.Algorithm {
	case "rsa-sha256":
		newHash, cryptoHash, keyType = sha256.New, crypto.SHA256, "rsa"
	case "ed25519-sha256":
		newHash, cryptoHash, keyType = sha256.New, crypto.SHA256, "ed25519"
	case "rsa-sha1":
		// RFC 8301 deprecates rsa-sha1 outright: SHA-1 collisions are
		// practical, so accepting it would let an attacker forge a signature.
		out.Result = DKIMPolicy
		out.Explanation = "rsa-sha1 is prohibited by RFC 8301"
		return out
	default:
		out.Explanation = fmt.Sprintf("unsupported signing algorithm %q", out.Algorithm)
		return out
	}

	// -- Timestamps ---------------------------------------------------------

	if expiry := strings.TrimSpace(tags["x"]); expiry != "" {
		seconds, err := strconv.ParseInt(expiry, 10, 64)
		if err != nil {
			out.Explanation = "x= tag is not an integer"
			return out
		}
		if now.After(time.Unix(seconds, 0)) {
			out.Expired = true
			out.Result = DKIMFail
			out.Explanation = fmt.Sprintf("signature expired at %s", time.Unix(seconds, 0).UTC().Format(time.RFC3339))
			return out
		}
	}
	if stamp := strings.TrimSpace(tags["t"]); stamp != "" {
		if seconds, err := strconv.ParseInt(stamp, 10, 64); err == nil {
			if time.Unix(seconds, 0).After(now.Add(48 * time.Hour)) {
				out.TimestampFuture = true
			}
		}
	}

	// -- Canonicalisation ---------------------------------------------------

	headerCanon, bodyCanon := "simple", "simple"
	if c := strings.TrimSpace(tags["c"]); c != "" {
		parts := strings.SplitN(c, "/", 2)
		headerCanon = strings.ToLower(strings.TrimSpace(parts[0]))
		if len(parts) == 2 {
			bodyCanon = strings.ToLower(strings.TrimSpace(parts[1]))
		}
	}
	if headerCanon != "simple" && headerCanon != "relaxed" {
		out.Explanation = fmt.Sprintf("unsupported header canonicalisation %q", headerCanon)
		return out
	}
	if bodyCanon != "simple" && bodyCanon != "relaxed" {
		out.Explanation = fmt.Sprintf("unsupported body canonicalisation %q", bodyCanon)
		return out
	}

	// -- Body hash ----------------------------------------------------------

	canonicalBody := canonicalizeBody(body, bodyCanon)
	out.BodyBytes = len(canonicalBody)
	out.SignedBytes = len(canonicalBody)

	if lengthTag := strings.TrimSpace(tags["l"]); lengthTag != "" {
		length, err := strconv.Atoi(lengthTag)
		if err != nil || length < 0 {
			out.Explanation = "l= tag is not a non-negative integer"
			return out
		}
		if length < len(canonicalBody) {
			// The signature only covers a prefix. Anything appended after it
			// is unsigned, which is the classic DKIM body-append attack.
			out.BodyTruncated = true
			canonicalBody = canonicalBody[:length]
		}
		out.SignedBytes = len(canonicalBody)
	}

	bodyHasher := newHash()
	bodyHasher.Write(canonicalBody)
	computedBodyHash := bodyHasher.Sum(nil)

	expectedBodyHash, err := base64.StdEncoding.DecodeString(bodyHashB64)
	if err != nil {
		out.Explanation = "bh= tag is not valid base64"
		return out
	}

	// Constant-time comparison: never branch on secret- or attacker-supplied
	// digest material with a variable-time compare.
	if subtle.ConstantTimeCompare(computedBodyHash, expectedBodyHash) != 1 {
		out.Result = DKIMFail
		out.Explanation = "body hash does not match the bh= tag; the body was modified in transit"
		return out
	}

	// -- Public key ---------------------------------------------------------

	keyRecord, keyErr := fetchDKIMKey(resolver, out.Selector, out.Domain)
	if keyErr != nil {
		out.Result = keyErr.result
		out.Explanation = keyErr.msg
		return out
	}

	if keyRecord.keyType != "" && keyRecord.keyType != keyType {
		out.Result = DKIMPermError
		out.Explanation = fmt.Sprintf("key record declares k=%s but the signature uses %s", keyRecord.keyType, keyType)
		return out
	}

	// -- Header hash --------------------------------------------------------

	headerInput := buildSignedHeaderInput(headers, sigIndex, signedHeaderNames, rawSig, headerCanon, fieldName)

	headerHasher := newHash()
	headerHasher.Write(headerInput)
	headerDigest := headerHasher.Sum(nil)

	signature, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		out.Explanation = "b= tag is not valid base64"
		return out
	}

	// -- Signature verification ---------------------------------------------

	switch keyType {
	case "rsa":
		pub, ok := keyRecord.key.(*rsa.PublicKey)
		if !ok {
			out.Result = DKIMPermError
			out.Explanation = "key record does not contain an RSA public key"
			return out
		}
		out.KeyBits = pub.N.BitLen()
		if out.KeyBits < minRSAKeyBits {
			out.Result = DKIMPolicy
			out.Explanation = fmt.Sprintf("RSA key is %d bits, below the %d-bit minimum in RFC 8301",
				out.KeyBits, minRSAKeyBits)
			return out
		}
		if err := rsa.VerifyPKCS1v15(pub, cryptoHash, headerDigest, signature); err != nil {
			out.Result = DKIMFail
			out.Explanation = "signature does not verify against the published key"
			return out
		}

	case "ed25519":
		pub, ok := keyRecord.key.(ed25519.PublicKey)
		if !ok {
			out.Result = DKIMPermError
			out.Explanation = "key record does not contain an Ed25519 public key"
			return out
		}
		out.KeyBits = 256
		// RFC 8463: Ed25519-SHA256 signs the SHA-256 digest of the header set.
		if !ed25519.Verify(pub, headerDigest, signature) {
			out.Result = DKIMFail
			out.Explanation = "signature does not verify against the published key"
			return out
		}
	}

	out.Result = DKIMPass
	if out.BodyTruncated {
		out.Explanation = fmt.Sprintf(
			"signature verified but covers only %d of %d body bytes (l= tag); trailing content is unsigned",
			out.SignedBytes, out.BodyBytes)
	} else {
		out.Explanation = "signature verified"
	}
	return out
}

// dkimKey is a parsed DKIM public-key record.
type dkimKey struct {
	key     crypto.PublicKey
	keyType string
	flags   string
}

type dkimKeyError struct {
	result string
	msg    string
}

// fetchDKIMKey retrieves and parses the public key for a selector.
func fetchDKIMKey(resolver *dnsx.Resolver, selector, domain string) (*dkimKey, *dkimKeyError) {
	name := selector + "._domainkey." + domain
	records := resolver.LookupTXT(name)
	if len(records) == 0 {
		// Fail closed: no key means the signature cannot be trusted. This is
		// a permerror rather than a temperror because a missing selector is
		// normally permanent, and treating it as temporary would let a
		// forger induce indefinite retries.
		return nil, &dkimKeyError{DKIMPermError, fmt.Sprintf("no DKIM key published at %s", name)}
	}

	// A selector may split its record across TXT strings.
	record := strings.Join(records, "")
	if len(record) > maxPublicKeyBytes {
		return nil, &dkimKeyError{DKIMPermError, "DKIM key record exceeds the size limit"}
	}

	tags, tagErr := parseStrictDKIMTags(record)
	if tagErr != nil {
		return nil, &dkimKeyError{DKIMPermError, tagErr.Error()}
	}

	if v := strings.TrimSpace(tags["v"]); v != "" && !strings.EqualFold(v, "DKIM1") {
		return nil, &dkimKeyError{DKIMPermError, fmt.Sprintf("unsupported key record version %q", v)}
	}

	keyType := strings.ToLower(strings.TrimSpace(tags["k"]))
	if keyType == "" {
		keyType = "rsa" // RFC 6376 default
	}

	encoded := stripWhitespace(tags["p"])
	if encoded == "" {
		// An empty p= means the key was revoked.
		return nil, &dkimKeyError{DKIMPermError, "DKIM key has been revoked (empty p= tag)"}
	}

	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, &dkimKeyError{DKIMPermError, "DKIM key p= tag is not valid base64"}
	}

	result := &dkimKey{keyType: keyType, flags: tags["t"]}

	switch keyType {
	case "rsa":
		pub, err := x509.ParsePKIXPublicKey(der)
		if err != nil {
			// Some publishers emit a bare PKCS#1 key rather than PKIX.
			if pkcs1, err1 := x509.ParsePKCS1PublicKey(der); err1 == nil {
				result.key = pkcs1
				return result, nil
			}
			return nil, &dkimKeyError{DKIMPermError, fmt.Sprintf("cannot parse RSA key: %v", err)}
		}
		rsaKey, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, &dkimKeyError{DKIMPermError, "k=rsa but the key is not RSA"}
		}
		result.key = rsaKey

	case "ed25519":
		if len(der) != ed25519.PublicKeySize {
			return nil, &dkimKeyError{DKIMPermError,
				fmt.Sprintf("Ed25519 key is %d bytes, expected %d", len(der), ed25519.PublicKeySize)}
		}
		result.key = ed25519.PublicKey(der)

	default:
		return nil, &dkimKeyError{DKIMPermError, fmt.Sprintf("unsupported key type %q", keyType)}
	}

	return result, nil
}

// buildSignedHeaderInput assembles the exact byte sequence the signature
// covers: each named header in h= order, followed by the DKIM-Signature
// field itself with its b= value emptied.
func buildSignedHeaderInput(headers [][2]string, sigIndex int, names []string, rawSig, canon, signatureField string) []byte {
	var sb strings.Builder

	// RFC 6376 section 5.4.2: for each name in h=, take the last unused
	// instance of that field, working from the bottom of the header block
	// upward. Consuming instances rather than re-reading the first one is
	// what makes a duplicated header (the "double From" attack) fail to
	// verify instead of silently signing the attacker's copy.
	occurrences := make(map[string][]int)
	for i, h := range headers {
		if i == sigIndex {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(h[0]))
		occurrences[key] = append(occurrences[key], i)
	}

	for _, name := range names {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}

		list := occurrences[key]
		if len(list) == 0 {
			// h= names an absent (or already consumed) field. RFC 6376 says
			// to treat it as the empty string and contribute nothing, which
			// is precisely how oversigning blocks header-addition attacks.
			continue
		}

		idx := list[len(list)-1]
		occurrences[key] = list[:len(list)-1]

		sb.WriteString(canonicalizeHeader(headers[idx][0], headers[idx][1], canon))
	}

	// The DKIM-Signature field is appended with an empty b= value and, in
	// simple canonicalisation, without a trailing CRLF.
	stripped := stripSignatureValue(rawSig)
	line := canonicalizeHeader(signatureField, stripped, canon)
	sb.WriteString(strings.TrimSuffix(line, "\r\n"))

	return []byte(sb.String())
}

// canonicalizeHeader applies RFC 6376 section 3.4.1 (simple) or 3.4.2
// (relaxed) canonicalisation to one header field.
func canonicalizeHeader(name, value, canon string) string {
	if canon == "relaxed" {
		// Lowercase the name, unfold the value, collapse internal whitespace
		// runs to a single space, and strip trailing whitespace.
		name = strings.ToLower(strings.TrimSpace(name))
		value = unfold(value)
		value = collapseWhitespace(value)
		value = strings.TrimSpace(value)
		return name + ":" + value + "\r\n"
	}
	// Simple canonicalisation leaves the field exactly as received.
	return name + ":" + value + "\r\n"
}

// canonicalizeBody applies body canonicalisation.
func canonicalizeBody(body []byte, canon string) []byte {
	// Normalise to CRLF line endings first; a message that reached us over a
	// pipe or a file may have been stripped to LF.
	text := strings.ReplaceAll(string(body), "\r\n", "\n")
	text = strings.ReplaceAll(text, "\n", "\r\n")

	if canon == "relaxed" {
		lines := strings.Split(text, "\r\n")
		for i, line := range lines {
			// Collapse whitespace runs and strip trailing whitespace.
			lines[i] = strings.TrimRight(collapseWhitespace(line), " \t")
		}
		text = strings.Join(lines, "\r\n")
	}

	// Both canonicalisations reduce trailing empty lines to a single CRLF,
	// and an entirely empty body canonicalises to the empty string in
	// relaxed mode and to a single CRLF in simple mode.
	text = strings.TrimRight(text, "\r\n")
	if text == "" {
		if canon == "relaxed" {
			return nil
		}
		return []byte("\r\n")
	}
	return []byte(text + "\r\n")
}

// bTagPattern matches the b= tag of a DKIM-Signature: a tag boundary (start
// of value or a semicolon), optional folding whitespace, the literal "b",
// optional whitespace, "=", then the value up to the next semicolon. The
// capture group keeps everything up to and including the equals sign so the
// value alone is removed.
var bTagPattern = regexp.MustCompile(`(?s)(^|;)([ \t\r\n]*b[ \t\r\n]*=)[^;]*`)

// stripSignatureValue empties the b= tag of a DKIM-Signature value while
// leaving every other byte, including whitespace and folding, intact. RFC
// 6376 section 3.7 requires the signature field to be hashed with its own
// signature value removed but otherwise unchanged.
func stripSignatureValue(sig string) string {
	return bTagPattern.ReplaceAllString(sig, "${1}${2}")
}

// parseDKIMTags parses a semicolon-separated tag list.
func parseDKIMTags(s string) map[string]string {
	tags := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(part[:eq]))
		if key == "" {
			continue
		}
		// Only the first occurrence of a tag is significant; a duplicate is
		// an attempt to make two parsers disagree.
		if _, exists := tags[key]; exists {
			continue
		}
		tags[key] = strings.TrimSpace(part[eq+1:])
	}
	return tags
}

// parseStrictDKIMTags enforces RFC 6376's lowercase, unique tag names for
// cryptographic material. The lenient parser remains for non-DKIM tag-list
// formats such as ARC-Authentication-Results instance discovery.
func parseStrictDKIMTags(s string) (map[string]string, error) {
	tags := make(map[string]string)
	for _, part := range strings.Split(s, ";") {
		eq := strings.Index(part, "=")
		if eq < 0 {
			continue
		}
		key := strings.TrimSpace(part[:eq])
		if key == "" {
			continue
		}
		if key != strings.ToLower(key) {
			return nil, fmt.Errorf("DKIM tag name %q must be lowercase", key)
		}
		if _, exists := tags[key]; exists {
			return nil, fmt.Errorf("duplicate DKIM tag %q", key)
		}
		tags[key] = strings.TrimSpace(part[eq+1:])
	}
	return tags, nil
}

// countHeader counts how many times a field name appears.
func countHeader(headers [][2]string, name string) int {
	count := 0
	for _, h := range headers {
		if strings.EqualFold(strings.TrimSpace(h[0]), name) {
			count++
		}
	}
	return count
}

func splitHeaderList(s string) []string {
	var out []string
	for _, name := range strings.Split(s, ":") {
		name = strings.TrimSpace(name)
		if name != "" {
			out = append(out, name)
		}
	}
	return out
}

func containsFold(list []string, want string) bool {
	for _, item := range list {
		if strings.EqualFold(strings.TrimSpace(item), want) {
			return true
		}
	}
	return false
}

func stripWhitespace(s string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '\t', '\r', '\n':
			return -1
		}
		return r
	}, s)
}

func unfold(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}

func collapseWhitespace(s string) string {
	var out strings.Builder
	inSpace := false
	for i := 0; i < len(s); i++ {
		if isSpaceByte(s[i]) {
			if !inSpace {
				out.WriteByte(' ')
				inSpace = true
			}
			continue
		}
		inSpace = false
		out.WriteByte(s[i])
	}
	return out.String()
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\r' || b == '\n'
}

package authverify

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

func TestStrictDKIMTagsRejectUppercaseAndDuplicates(t *testing.T) {
	if _, err := parseStrictDKIMTags("v=1; B=bad; b=good"); err == nil {
		t.Fatal("uppercase tag name must be rejected")
	}
	if _, err := parseStrictDKIMTags("v=1; b=one; b=two"); err == nil {
		t.Fatal("duplicate tag must be rejected")
	}
}

// signer builds DKIM-signed messages for tests. It mirrors what a real
// signing MTA does, so the verifier is exercised against genuine signatures
// rather than fixtures that could drift from the implementation.
type signer struct {
	rsaKey     *rsa.PrivateKey
	ed25519Key ed25519.PrivateKey
	domain     string
	selector   string
	headerCan  string
	bodyCan    string
}

func newSigner(t *testing.T, bits int) *signer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return &signer{
		rsaKey:    key,
		domain:    "example.com",
		selector:  "sel",
		headerCan: "relaxed",
		bodyCan:   "relaxed",
	}
}

// publish registers the signer's public key in the test zone.
func (s *signer) publish(t *testing.T, b *dnsx.StaticBackend) {
	t.Helper()

	name := s.selector + "._domainkey." + s.domain
	if s.ed25519Key != nil {
		pub := s.ed25519Key.Public().(ed25519.PublicKey)
		b.AddTXT(name, "v=DKIM1; k=ed25519; p="+base64.StdEncoding.EncodeToString(pub))
		return
	}

	der, err := x509.MarshalPKIXPublicKey(&s.rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	b.AddTXT(name, "v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(der))
}

// sign returns the header pairs for a signed message.
func (s *signer) sign(t *testing.T, headers [][2]string, body []byte, extraTags string) [][2]string {
	t.Helper()

	canonBody := canonicalizeBody(body, s.bodyCan)
	bodyHash := sha256.Sum256(canonBody)

	var names []string
	for _, h := range headers {
		names = append(names, strings.ToLower(h[0]))
	}

	algorithm := "rsa-sha256"
	if s.ed25519Key != nil {
		algorithm = "ed25519-sha256"
	}

	sigValue := " v=1; a=" + algorithm +
		"; c=" + s.headerCan + "/" + s.bodyCan +
		"; d=" + s.domain +
		"; s=" + s.selector +
		"; h=" + strings.Join(names, ":") +
		"; bh=" + base64.StdEncoding.EncodeToString(bodyHash[:])
	if extraTags != "" {
		sigValue += "; " + extraTags
	}
	sigValue += "; b="

	// Build the signed header set exactly as the verifier will.
	withSig := append(append([][2]string{}, headers...), [2]string{"DKIM-Signature", sigValue})
	input := buildSignedHeaderInput(withSig, len(withSig)-1, names, sigValue, s.headerCan, "DKIM-Signature")
	digest := sha256.Sum256(input)

	var signature []byte
	var err error
	if s.ed25519Key != nil {
		signature = ed25519.Sign(s.ed25519Key, digest[:])
	} else {
		signature, err = rsa.SignPKCS1v15(rand.Reader, s.rsaKey, crypto.SHA256, digest[:])
		if err != nil {
			t.Fatalf("sign: %v", err)
		}
	}

	withSig[len(withSig)-1][1] = sigValue + base64.StdEncoding.EncodeToString(signature)
	return withSig
}

func baseHeaders() [][2]string {
	return [][2]string{
		{"From", " Alice <alice@example.com>"},
		{"To", " Bob <bob@example.net>"},
		{"Subject", " Quarterly report"},
		{"Date", " Mon, 27 Jul 2026 10:00:00 +0000"},
	}
}

func TestDKIMPassWithValidRSASignature(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048)
	s.publish(t, backend)

	body := []byte("This is the report.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Result != DKIMPass {
		t.Fatalf("expected pass, got %s: %s", got.Result, got.Signatures[0].Explanation)
	}
	if len(got.PassingDomains) != 1 || got.PassingDomains[0] != "example.com" {
		t.Errorf("expected example.com to pass, got %v", got.PassingDomains)
	}
	if got.Signatures[0].KeyBits != 2048 {
		t.Errorf("expected 2048-bit key, got %d", got.Signatures[0].KeyBits)
	}
}

func TestDKIMPassWithEd25519Signature(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	s := &signer{ed25519Key: priv, domain: "example.com", selector: "ed", headerCan: "relaxed", bodyCan: "relaxed"}
	s.publish(t, backend)

	body := []byte("Signed with Ed25519.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Result != DKIMPass {
		t.Fatalf("expected pass, got %s: %s", got.Result, got.Signatures[0].Explanation)
	}
}

func TestDKIMSimpleCanonicalization(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048)
	s.headerCan, s.bodyCan = "simple", "simple"
	s.publish(t, backend)

	body := []byte("Simple canonicalisation.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Result != DKIMPass {
		t.Fatalf("expected pass with simple canonicalisation, got %s: %s",
			got.Result, got.Signatures[0].Explanation)
	}
}

// -- Negative paths ---------------------------------------------------------

func TestDKIMFailsOnTamperedBody(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048)
	s.publish(t, backend)

	body := []byte("Wire 1000 dollars to account 12345.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	tampered := []byte("Wire 9999 dollars to account 99999.\r\n")

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, tampered, time.Now())
	if got.Result != DKIMFail {
		t.Fatalf("expected fail on a tampered body, got %s", got.Result)
	}
	if !strings.Contains(got.Signatures[0].Explanation, "body hash") {
		t.Errorf("expected a body-hash explanation, got %q", got.Signatures[0].Explanation)
	}
}

func TestDKIMFailsOnTamperedHeader(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048)
	s.publish(t, backend)

	body := []byte("Body.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	// Rewrite the signed Subject after signing.
	for i := range headers {
		if strings.EqualFold(headers[i][0], "Subject") {
			headers[i][1] = " URGENT: wire transfer approved"
		}
	}

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Result != DKIMFail {
		t.Fatalf("expected fail on a tampered header, got %s", got.Result)
	}
}

func TestDKIMFailsWithWrongKey(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048)

	// Publish an unrelated key at the selector.
	other := newSigner(t, 2048)
	other.domain, other.selector = s.domain, s.selector
	other.publish(t, backend)

	body := []byte("Body.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Result != DKIMFail {
		t.Fatalf("expected fail against the wrong key, got %s: %s",
			got.Result, got.Signatures[0].Explanation)
	}
}

func TestDKIMFailsOnExpiredSignature(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048)
	s.publish(t, backend)

	body := []byte("Body.\r\n")
	expiry := time.Now().Add(-1 * time.Hour).Unix()
	headers := s.sign(t, baseHeaders(), body, "x="+itoa(int(expiry)))

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Result != DKIMFail {
		t.Fatalf("expected fail for an expired signature, got %s", got.Result)
	}
	if !got.Signatures[0].Expired {
		t.Error("expected the Expired flag to be set")
	}
}

// RFC 8301 prohibits rsa-sha1: SHA-1 collisions are practical.
func TestDKIMRejectsSHA1(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	headers := append(baseHeaders(), [2]string{"DKIM-Signature",
		" v=1; a=rsa-sha1; c=relaxed/relaxed; d=example.com; s=sel; h=from; bh=AAAA; b=BBBB"})

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, []byte("x"), time.Now())
	if got.Signatures[0].Result != DKIMPolicy {
		t.Fatalf("expected a policy rejection for rsa-sha1, got %s", got.Signatures[0].Result)
	}
}

// An undersized RSA key must not be accepted even if the maths verifies.
func TestDKIMRejectsUndersizedKey(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 512)
	s.publish(t, backend)

	body := []byte("Body.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Signatures[0].Result != DKIMPolicy {
		t.Fatalf("expected a policy rejection for a 512-bit key, got %s: %s",
			got.Signatures[0].Result, got.Signatures[0].Explanation)
	}
}

// A signature that does not cover From says nothing about who sent the
// message, which is the only identity a filter cares about.
func TestDKIMRejectsUnsignedFrom(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	headers := append(baseHeaders(), [2]string{"DKIM-Signature",
		" v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=sel; h=subject:to; bh=AAAA; b=BBBB"})

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, []byte("x"), time.Now())
	if got.Signatures[0].Result != DKIMPermError {
		t.Fatalf("expected permerror when From is unsigned, got %s", got.Signatures[0].Result)
	}
	if !strings.Contains(got.Signatures[0].Explanation, "From") {
		t.Errorf("expected the explanation to mention From, got %q", got.Signatures[0].Explanation)
	}
}

// A revoked key (empty p=) must fail rather than being treated as absent.
func TestDKIMRevokedKeyFails(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTXT("sel._domainkey.example.com", "v=DKIM1; k=rsa; p=")

	s := newSigner(t, 2048)
	body := []byte("Body.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Signatures[0].Result != DKIMPermError {
		t.Fatalf("expected permerror for a revoked key, got %s", got.Signatures[0].Result)
	}
	if !strings.Contains(got.Signatures[0].Explanation, "revoked") {
		t.Errorf("expected a revocation explanation, got %q", got.Signatures[0].Explanation)
	}
}

func TestDKIMMissingKeyFailsClosed(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048) // never published

	body := []byte("Body.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, body, time.Now())
	if got.Result == DKIMPass {
		t.Fatal("a signature with no published key must never pass")
	}
}

// The l= tag lets a signer cover only a prefix of the body. Everything after
// it is unsigned and can be replaced, so a pass must be reported with the
// truncation flag rather than as a clean authentication of the content.
func TestDKIMBodyLengthTagIsFlagged(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048)
	s.publish(t, backend)

	original := []byte("Legitimate content.\r\n")
	canonLen := len(canonicalizeBody(original, s.bodyCan))
	headers := s.sign(t, baseHeaders(), original, "l="+itoa(canonLen))

	// An attacker appends to the body; the signature still verifies.
	appended := append(append([]byte{}, original...), []byte("PS: send money to evil.example\r\n")...)

	got := VerifyDKIM(dnsx.NewTestResolver(backend), headers, appended, time.Now())
	if got.Result != DKIMPass {
		t.Fatalf("expected the truncated signature to still verify, got %s: %s",
			got.Result, got.Signatures[0].Explanation)
	}
	if !got.Signatures[0].BodyTruncated {
		t.Fatal("expected BodyTruncated to be set; an unsigned suffix must not be hidden")
	}
	if got.Signatures[0].SignedBytes >= got.Signatures[0].BodyBytes {
		t.Errorf("expected signed bytes (%d) to be fewer than body bytes (%d)",
			got.Signatures[0].SignedBytes, got.Signatures[0].BodyBytes)
	}
}

// Adding a second From after signing must not verify: the verifier consumes
// header instances bottom-up, so the attacker's prepended copy is not the one
// that was signed.
func TestDKIMDuplicateFromDoesNotVerify(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	s := newSigner(t, 2048)
	s.publish(t, backend)

	body := []byte("Body.\r\n")
	signed := s.sign(t, baseHeaders(), body, "")

	// Prepend a forged From ahead of the signed one.
	attacked := append([][2]string{{"From", " Boss <boss@victim.example>"}}, signed...)

	got := VerifyDKIM(dnsx.NewTestResolver(backend), attacked, body, time.Now())
	if got.Result == DKIMPass {
		t.Fatal("a message with an injected second From must not verify")
	}
}

func TestDKIMNoSignatureIsNone(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	got := VerifyDKIM(dnsx.NewTestResolver(backend), baseHeaders(), []byte("x"), time.Now())
	if got.Result != DKIMNone {
		t.Fatalf("expected none for an unsigned message, got %s", got.Result)
	}
}

func TestDKIMWithoutResolverFailsClosed(t *testing.T) {
	s := newSigner(t, 2048)
	body := []byte("Body.\r\n")
	headers := s.sign(t, baseHeaders(), body, "")

	got := VerifyDKIM(nil, headers, body, time.Now())
	if got.Result == DKIMPass {
		t.Fatal("verification without a resolver must never report pass")
	}
	if got.Result != DKIMTempError {
		t.Errorf("expected temperror without a resolver, got %s", got.Result)
	}
}

func TestStripSignatureValueRemovesOnlyB(t *testing.T) {
	in := " v=1; a=rsa-sha256; d=example.com; bh=ABC123; b=SIGNATUREDATA; s=sel"
	out := stripSignatureValue(in)

	if strings.Contains(out, "SIGNATUREDATA") {
		t.Errorf("b= value was not removed: %q", out)
	}
	if !strings.Contains(out, "bh=ABC123") {
		t.Errorf("bh= must be preserved: %q", out)
	}
	if !strings.Contains(out, "s=sel") {
		t.Errorf("trailing tags must be preserved: %q", out)
	}
	if !strings.Contains(out, "b=") {
		t.Errorf("the b= tag itself must remain: %q", out)
	}
}

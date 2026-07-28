package rules_test

// End-to-end DKIM verification over the production path: wire bytes ->
// ParseMessage -> RawHeaderPairs -> VerifyDKIM.
//
// The in-package tests in pkg/authverify sign and verify the same in-memory
// header slice, so they never exercise the parser. That gap hid a defect
// where folded fields were rejoined with LF instead of CRLF, which broke
// every simple-canonicalised signature: the DKIM-Signature field is itself
// always folded, so it was not an edge case.
//
// This lives in an external test package because pkg/rules imports
// pkg/authverify, and an in-package test importing authverify would cycle.

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/afterdarksys/mailscript/pkg/authverify"
	"github.com/afterdarksys/mailscript/pkg/dnsx"
	"github.com/afterdarksys/mailscript/pkg/rules"
)

// signSimple builds a message signed with simple/simple canonicalisation.
//
// The canonicalisation is written out longhand rather than reusing the
// verifier's helpers, so the test pins the RFC 6376 behaviour rather than
// whatever the implementation currently does.
func signSimple(t *testing.T, key *rsa.PrivateKey, fields [][2]string, body string, foldSignature bool) string {
	t.Helper()

	// Simple body canonicalisation: strip trailing empty lines, end with CRLF.
	canonBody := strings.TrimRight(body, "\r\n") + "\r\n"
	bodyHash := sha256.Sum256([]byte(canonBody))

	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, strings.ToLower(f[0]))
	}

	sigTags := "v=1; a=rsa-sha256; c=simple/simple; d=example.com; s=sel; " +
		"h=" + strings.Join(names, ":") + "; " +
		"bh=" + base64.StdEncoding.EncodeToString(bodyHash[:]) + "; b="

	// Simple header canonicalisation is the field exactly as it appears,
	// followed by CRLF; the signature field itself carries no trailing CRLF.
	var input strings.Builder
	for _, f := range fields {
		input.WriteString(f[0] + ":" + f[1] + "\r\n")
	}
	input.WriteString("DKIM-Signature:" + " " + sigTags)

	digest := sha256.Sum256([]byte(input.String()))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	b64 := base64.StdEncoding.EncodeToString(signature)

	sigValue := " " + sigTags + b64
	if foldSignature {
		// Fold the signature field the way a real signer does: the b= value
		// is far longer than the 78-column recommendation.
		half := len(b64) / 2
		sigValue = " " + sigTags + b64[:half] + "\r\n\t" + b64[half:]
	}

	var raw strings.Builder
	raw.WriteString("DKIM-Signature:" + sigValue + "\r\n")
	for _, f := range fields {
		raw.WriteString(f[0] + ":" + f[1] + "\r\n")
	}
	raw.WriteString("\r\n")
	raw.WriteString(body)
	return raw.String()
}

func publishKey(t *testing.T, backend *dnsx.StaticBackend, key *rsa.PrivateKey) {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	backend.AddTXT("sel._domainkey.example.com",
		"v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(der))
}

func verifyWire(t *testing.T, backend *dnsx.StaticBackend, wire string) authverify.DKIMResult {
	t.Helper()
	ctx, err := rules.ParseMessage([]byte(wire))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return authverify.VerifyDKIM(dnsx.NewTestResolver(backend),
		ctx.RawHeaderPairs(), ctx.RawBody, time.Now())
}

func TestDKIMSimpleCanonUnfoldedField(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	backend := dnsx.NewStaticBackend()
	publishKey(t, backend, key)

	fields := [][2]string{
		{"From", " Alice <alice@example.com>"},
		{"Subject", " Short subject"},
	}
	wire := signSimple(t, key, fields, "Body text.\r\n", false)

	if got := verifyWire(t, backend, wire); got.Result != authverify.DKIMPass {
		t.Fatalf("expected pass, got %s: %s", got.Result, got.Signatures[0].Explanation)
	}
}

// A folded signed field must survive the parser byte for byte.
func TestDKIMSimpleCanonFoldedSignedField(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	backend := dnsx.NewStaticBackend()
	publishKey(t, backend, key)

	fields := [][2]string{
		{"From", " Alice <alice@example.com>"},
		{"Subject", " this subject is long enough that a sender would\r\n fold it across two lines"},
	}
	wire := signSimple(t, key, fields, "Body text.\r\n", false)

	if got := verifyWire(t, backend, wire); got.Result != authverify.DKIMPass {
		t.Fatalf("folded signed field must verify under simple canonicalisation, got %s: %s",
			got.Result, got.Signatures[0].Explanation)
	}
}

// The DKIM-Signature field is itself folded on virtually every real message,
// because the base64 b= value is several hundred characters.
func TestDKIMSimpleCanonFoldedSignatureField(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	backend := dnsx.NewStaticBackend()
	publishKey(t, backend, key)

	fields := [][2]string{
		{"From", " Alice <alice@example.com>"},
		{"Subject", " Quarterly report"},
	}
	wire := signSimple(t, key, fields, "Body text.\r\n", true)

	if got := verifyWire(t, backend, wire); got.Result != authverify.DKIMPass {
		t.Fatalf("a folded DKIM-Signature must verify, got %s: %s",
			got.Result, got.Signatures[0].Explanation)
	}
}

// Tampering must still be caught once the fold handling is correct, so the
// fix cannot have been to simply ignore the affected bytes.
func TestDKIMWireTamperStillFails(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	backend := dnsx.NewStaticBackend()
	publishKey(t, backend, key)

	fields := [][2]string{
		{"From", " Alice <alice@example.com>"},
		{"Subject", " this subject is long enough that a sender would\r\n fold it across two lines"},
	}
	wire := signSimple(t, key, fields, "Wire 100 dollars.\r\n", true)

	tampered := strings.Replace(wire, "Wire 100 dollars.", "Wire 9999 dollars.", 1)
	if got := verifyWire(t, backend, tampered); got.Result == authverify.DKIMPass {
		t.Fatal("a tampered body must not verify")
	}

	reworded := strings.Replace(wire, "fold it across two lines", "fold it across TWO lines", 1)
	if got := verifyWire(t, backend, reworded); got.Result == authverify.DKIMPass {
		t.Fatal("a tampered folded header must not verify")
	}
}

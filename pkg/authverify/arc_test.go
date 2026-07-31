package authverify

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"testing"
	"time"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

func TestVerifyARCOneSet(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	backend := dnsx.NewStaticBackend().AddTXT("arc._domainkey.example.com",
		"v=DKIM1; k=rsa; p="+base64.StdEncoding.EncodeToString(pubDER))
	resolver := dnsx.NewTestResolver(backend)
	body := []byte("hello\r\n")
	bodyDigest := sha256.Sum256(canonicalizeBody(body, "relaxed"))

	ams := "i=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=arc; " +
		"h=from:subject; bh=" + base64.StdEncoding.EncodeToString(bodyDigest[:]) + "; b="
	headers := [][2]string{
		{"From", "sender@example.com"},
		{"Subject", "test"},
		{"ARC-Authentication-Results", "i=1; mx.example; spf=pass"},
		{"ARC-Message-Signature", ams},
		{"ARC-Seal", "i=1; a=rsa-sha256; d=example.com; s=arc; cv=none; b="},
	}
	amsInput := buildSignedHeaderInput(headers, 3, []string{"from", "subject"}, ams, "relaxed", "ARC-Message-Signature")
	amsDigest := sha256.Sum256(amsInput)
	amsSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, amsDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	headers[3][1] = ams + base64.StdEncoding.EncodeToString(amsSig)

	sets := map[int]*arcSet{1: {instance: 1, aarIndex: 2, amsIndex: 3, asIndex: 4}}
	sealDigest := sha256.Sum256(buildARCSealInput(headers, sets, 1))
	sealSig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, sealDigest[:])
	if err != nil {
		t.Fatal(err)
	}
	headers[4][1] += base64.StdEncoding.EncodeToString(sealSig)

	got := VerifyARC(resolver, headers, body, time.Now())
	if got.Result != "pass" || len(got.Sets) != 1 || got.Sets[0].Seal != "pass" {
		t.Fatalf("unexpected ARC result: %+v", got)
	}
}

func TestVerifyARCRejectsIncompleteSet(t *testing.T) {
	headers := [][2]string{{"ARC-Seal", "i=1; cv=none"}}
	got := VerifyARC(dnsx.NewTestResolver(dnsx.NewStaticBackend()), headers, nil, time.Now())
	if got.Result != "permerror" {
		t.Fatalf("expected permerror, got %+v", got)
	}
}

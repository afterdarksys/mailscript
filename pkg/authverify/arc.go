package authverify

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

// ARCSetResult is the cryptographic outcome for one ARC set (RFC 8617).
type ARCSetResult struct {
	Instance         int
	Domain           string
	Selector         string
	ChainValidation  string
	MessageSignature string
	Seal             string
	Explanation      string
}

// ARCResult is the locally verified ARC chain. A reported arc=pass header is
// never used here; every message signature and seal is checked against DNS.
type ARCResult struct {
	Result      string
	Sets        []ARCSetResult
	Explanation string
}

type arcSet struct {
	instance int
	aarIndex int
	amsIndex int
	asIndex  int
}

// VerifyARC verifies ARC set structure, each ARC-Message-Signature, and each
// ARC-Seal. It returns none when the message carries no ARC fields.
func VerifyARC(resolver *dnsx.Resolver, headers [][2]string, body []byte, now time.Time) ARCResult {
	out := ARCResult{Result: "none", Explanation: "no ARC chain present"}
	sets := map[int]*arcSet{}
	arcFields := 0
	for index, h := range headers {
		name := strings.ToLower(strings.TrimSpace(h[0]))
		if name != "arc-authentication-results" && name != "arc-message-signature" && name != "arc-seal" {
			continue
		}
		arcFields++
		instance, err := arcInstance(h[1])
		if err != nil || instance < 1 || instance > 50 {
			out.Result = "permerror"
			out.Explanation = fmt.Sprintf("invalid ARC instance on %s", h[0])
			return out
		}
		set := sets[instance]
		if set == nil {
			set = &arcSet{instance: instance, aarIndex: -1, amsIndex: -1, asIndex: -1}
			sets[instance] = set
		}
		slot := &set.aarIndex
		if name == "arc-message-signature" {
			slot = &set.amsIndex
		} else if name == "arc-seal" {
			slot = &set.asIndex
		}
		if *slot >= 0 {
			out.Result = "permerror"
			out.Explanation = fmt.Sprintf("duplicate %s for ARC instance %d", h[0], instance)
			return out
		}
		*slot = index
	}
	if arcFields == 0 {
		return out
	}
	if n := countHeader(headers, "From"); n != 1 {
		out.Result = "permerror"
		out.Explanation = fmt.Sprintf("ARC cannot authenticate a message with %d From fields", n)
		return out
	}
	if !resolver.Enabled() {
		out.Result = "temperror"
		out.Explanation = "no DNS resolver configured; ARC keys cannot be retrieved"
		return out
	}
	if now.IsZero() {
		now = time.Now()
	}

	for instance := 1; instance <= len(sets); instance++ {
		set := sets[instance]
		if set == nil || set.aarIndex < 0 || set.amsIndex < 0 || set.asIndex < 0 {
			out.Result = "permerror"
			out.Explanation = fmt.Sprintf("ARC sets must be consecutive and complete; instance %d is missing a field", instance)
			return out
		}
		detail := ARCSetResult{Instance: instance}
		sealTags, sealTagErr := parseStrictDKIMTags(headers[set.asIndex][1])
		if sealTagErr != nil {
			out.Result = "permerror"
			out.Explanation = sealTagErr.Error()
			return out
		}
		detail.Domain = strings.ToLower(sealTags["d"])
		detail.Selector = sealTags["s"]
		detail.ChainValidation = strings.ToLower(sealTags["cv"])
		expectedCV := "pass"
		if instance == 1 {
			expectedCV = "none"
		}
		if detail.ChainValidation != expectedCV {
			detail.Explanation = fmt.Sprintf("ARC-Seal cv=%s, expected %s", detail.ChainValidation, expectedCV)
			out.Sets = append(out.Sets, detail)
			out.Result = "fail"
			out.Explanation = detail.Explanation
			return out
		}

		// ARC-Message-Signature uses DKIM's signing algorithm and body hash;
		// the shared verifier retains the ARC field name during canonicalisation.
		ams := verifyOneMessageSignature(resolver, headers, set.amsIndex, body, now, "ARC-Message-Signature", false)
		for _, signed := range ams.HeadersSigned {
			switch strings.ToLower(signed) {
			case "authentication-results", "arc-authentication-results", "arc-message-signature", "arc-seal":
				ams.Result = DKIMPermError
				ams.Explanation = "ARC-Message-Signature must not cover Authentication-Results or ARC fields"
			}
		}
		detail.MessageSignature = ams.Result
		// Only the newest AMS is required to match the current message. An
		// earlier custodian's legitimate modification can invalidate an older
		// AMS; the seals still protect that historical signature and AAR.
		if ams.Result != DKIMPass && instance == len(sets) {
			detail.Explanation = "ARC-Message-Signature: " + ams.Explanation
			out.Sets = append(out.Sets, detail)
			out.Result = ams.Result
			out.Explanation = fmt.Sprintf("ARC instance %d message signature failed", instance)
			return out
		}

		sealResult, sealExplanation := verifyARCSeal(resolver, headers, sets, instance)
		detail.Seal = sealResult
		detail.Explanation = sealExplanation
		out.Sets = append(out.Sets, detail)
		if sealResult != DKIMPass {
			out.Result = sealResult
			out.Explanation = fmt.Sprintf("ARC instance %d seal failed: %s", instance, sealExplanation)
			return out
		}
	}
	out.Result = "pass"
	out.Explanation = fmt.Sprintf("all %d ARC set(s) cryptographically verified", len(out.Sets))
	return out
}

func arcInstance(value string) (int, error) {
	tags := parseDKIMTags(value)
	// AAR begins with i= but is not otherwise a DKIM tag list; parseDKIMTags
	// still safely extracts its first semicolon-delimited field.
	return strconv.Atoi(strings.TrimSpace(tags["i"]))
}

func verifyARCSeal(resolver *dnsx.Resolver, headers [][2]string, sets map[int]*arcSet, instance int) (string, string) {
	current := sets[instance]
	value := headers[current.asIndex][1]
	tags, tagErr := parseStrictDKIMTags(value)
	if tagErr != nil {
		return DKIMPermError, tagErr.Error()
	}
	domain, selector := strings.ToLower(tags["d"]), strings.TrimSpace(tags["s"])
	algorithm := strings.ToLower(tags["a"])
	if domain == "" || selector == "" || tags["b"] == "" || tags["i"] == "" || tags["cv"] == "" {
		return DKIMPermError, "ARC-Seal is missing a required i, a, b, d, s, or cv tag"
	}
	if algorithm != "rsa-sha256" && algorithm != "ed25519-sha256" {
		return DKIMPolicy, fmt.Sprintf("unsupported ARC-Seal algorithm %q", algorithm)
	}

	input := buildARCSealInput(headers, sets, instance)
	digest := sha256.Sum256(input)
	signature, err := base64.StdEncoding.DecodeString(stripWhitespace(tags["b"]))
	if err != nil {
		return DKIMPermError, "ARC-Seal b= is not valid base64"
	}
	key, keyErr := fetchDKIMKey(resolver, selector, domain)
	if keyErr != nil {
		return keyErr.result, keyErr.msg
	}
	switch algorithm {
	case "rsa-sha256":
		pub, ok := key.key.(*rsa.PublicKey)
		if !ok || pub.N.BitLen() < minRSAKeyBits {
			return DKIMPolicy, "ARC-Seal does not use an acceptable RSA key"
		}
		if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
			return DKIMFail, "seal signature does not verify"
		}
	case "ed25519-sha256":
		pub, ok := key.key.(ed25519.PublicKey)
		if !ok || !ed25519.Verify(pub, digest[:], signature) {
			return DKIMFail, "seal signature does not verify"
		}
	}
	return DKIMPass, "message signature and seal verified"
}

func buildARCSealInput(headers [][2]string, sets map[int]*arcSet, instance int) []byte {
	var input strings.Builder
	for n := 1; n <= instance; n++ {
		set := sets[n]
		input.WriteString(canonicalizeHeader(headers[set.aarIndex][0], headers[set.aarIndex][1], "relaxed"))
		input.WriteString(canonicalizeHeader(headers[set.amsIndex][0], headers[set.amsIndex][1], "relaxed"))
		sealValue := headers[set.asIndex][1]
		if n == instance {
			sealValue = stripSignatureValue(sealValue)
		}
		line := canonicalizeHeader(headers[set.asIndex][0], sealValue, "relaxed")
		if n == instance {
			line = strings.TrimSuffix(line, "\r\n")
		}
		input.WriteString(line)
	}
	return []byte(input.String())
}

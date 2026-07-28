package authverify

import (
	"testing"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

func TestDMARCPassRequiresAlignment(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTXT("_dmarc.example.com", "v=DMARC1; p=reject")
	resolver := dnsx.NewTestResolver(backend)

	// SPF passes, but for an unrelated envelope domain. DMARC must fail:
	// this is precisely the bounce-relay trick DMARC exists to stop.
	unaligned := VerifyDMARC(resolver, "example.com",
		SPFResult{Result: SPFPass, Domain: "bounces.mailer.example"},
		DKIMResult{Result: DKIMNone})
	if unaligned.Result != DMARCFail {
		t.Fatalf("expected fail for unaligned SPF, got %s", unaligned.Result)
	}
	if unaligned.Disposition != PolicyReject {
		t.Errorf("expected a reject disposition, got %q", unaligned.Disposition)
	}

	aligned := VerifyDMARC(resolver, "example.com",
		SPFResult{Result: SPFPass, Domain: "example.com"},
		DKIMResult{Result: DKIMNone})
	if aligned.Result != DMARCPass {
		t.Fatalf("expected pass for aligned SPF, got %s", aligned.Result)
	}
}

func TestDMARCRelaxedAlignmentAcceptsSubdomain(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTXT("_dmarc.example.com", "v=DMARC1; p=reject; aspf=r")
	resolver := dnsx.NewTestResolver(backend)

	got := VerifyDMARC(resolver, "example.com",
		SPFResult{Result: SPFPass, Domain: "mail.example.com"},
		DKIMResult{Result: DKIMNone})
	if got.Result != DMARCPass {
		t.Fatalf("relaxed alignment should accept a subdomain, got %s", got.Result)
	}
}

func TestDMARCStrictAlignmentRejectsSubdomain(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTXT("_dmarc.example.com", "v=DMARC1; p=reject; aspf=s")
	resolver := dnsx.NewTestResolver(backend)

	got := VerifyDMARC(resolver, "example.com",
		SPFResult{Result: SPFPass, Domain: "mail.example.com"},
		DKIMResult{Result: DKIMNone})
	if got.Result != DMARCFail {
		t.Fatalf("strict alignment must reject a subdomain, got %s", got.Result)
	}
}

func TestDMARCDKIMAlignmentPasses(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTXT("_dmarc.example.com", "v=DMARC1; p=quarantine")
	resolver := dnsx.NewTestResolver(backend)

	got := VerifyDMARC(resolver, "example.com",
		SPFResult{Result: SPFFail},
		DKIMResult{Result: DKIMPass, PassingDomains: []string{"example.com"}})
	if got.Result != DMARCPass {
		t.Fatalf("an aligned DKIM pass alone should satisfy DMARC, got %s", got.Result)
	}
	if !got.DKIMAligned {
		t.Error("expected DKIMAligned to be set")
	}
}

func TestDMARCFallsBackToOrganizationalDomain(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	// No record at the exact subdomain; one at the organisational domain.
	backend.AddTXT("_dmarc.example.com", "v=DMARC1; p=reject; sp=quarantine")
	resolver := dnsx.NewTestResolver(backend)

	got := VerifyDMARC(resolver, "mail.example.com",
		SPFResult{Result: SPFFail},
		DKIMResult{Result: DKIMFail})
	if got.Result != DMARCFail {
		t.Fatalf("expected fail, got %s", got.Result)
	}
	if got.Record == nil || !got.Record.Organizational {
		t.Fatal("expected the record to be marked as inherited from the organisational domain")
	}
	// sp= governs subdomains, so the disposition is quarantine, not reject.
	if got.Disposition != PolicyQuarantine {
		t.Errorf("expected sp=quarantine to apply, got %q", got.Disposition)
	}
}

func TestDMARCNoRecordIsNone(t *testing.T) {
	resolver := dnsx.NewTestResolver(dnsx.NewStaticBackend())

	got := VerifyDMARC(resolver, "nopolicy.example",
		SPFResult{Result: SPFFail}, DKIMResult{Result: DKIMFail})
	if got.Result != DMARCNone {
		t.Fatalf("expected none when no policy is published, got %s", got.Result)
	}
	if got.Disposition != PolicyNone {
		t.Errorf("absent policy must not imply enforcement, got %q", got.Disposition)
	}
}

// A staged rollout (pct<100) must not be treated as full enforcement.
func TestDMARCPercentSoftensReject(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTXT("_dmarc.example.com", "v=DMARC1; p=reject; pct=10")
	resolver := dnsx.NewTestResolver(backend)

	got := VerifyDMARC(resolver, "example.com",
		SPFResult{Result: SPFFail}, DKIMResult{Result: DKIMFail})
	if got.Disposition != PolicyQuarantine {
		t.Fatalf("expected pct<100 to soften reject to quarantine, got %q", got.Disposition)
	}
}

func TestDMARCParsesTagsAndDefaults(t *testing.T) {
	record := parseDMARCRecord("v=DMARC1; p=reject; adkim=s; pct=50; rua=mailto:a@b.example,mailto:c@d.example")

	if record.Policy != PolicyReject {
		t.Errorf("expected reject, got %q", record.Policy)
	}
	if record.ADKIM != "s" {
		t.Errorf("expected strict adkim, got %q", record.ADKIM)
	}
	if record.ASPF != "r" {
		t.Errorf("aspf should default to relaxed, got %q", record.ASPF)
	}
	if record.Percent != 50 {
		t.Errorf("expected pct=50, got %d", record.Percent)
	}
	if record.SubdomainPolicy != PolicyReject {
		t.Errorf("sp should default to p, got %q", record.SubdomainPolicy)
	}
	if len(record.RUA) != 2 {
		t.Errorf("expected two rua destinations, got %v", record.RUA)
	}
}

func TestDMARCWithoutResolverIsTempError(t *testing.T) {
	got := VerifyDMARC(nil, "example.com", SPFResult{}, DKIMResult{})
	if got.Result != DMARCTempError {
		t.Fatalf("expected temperror without a resolver, got %s", got.Result)
	}
}

// -- DANE -------------------------------------------------------------------

// TLSA records that were not DNSSEC-validated must never be reported as a
// pass: an attacker who can forge the answer can equally strip it.
func TestDANEUnvalidatedIsInsecure(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTLSA("_25._tcp.mx.example.com", dnsx.TLSAResult{
		Found:  true,
		Secure: false,
		Records: []dnsx.TLSARecord{
			{Usage: UsageDANEEE, Selector: 1, MatchingType: 1, Certificate: "abcd"},
		},
	})
	resolver := dnsx.NewTestResolver(backend)

	got := CheckDANE(resolver, "mx.example.com", 25)
	if got.Result != DANEInsecure {
		t.Fatalf("expected insecure without DNSSEC validation, got %s", got.Result)
	}
	if got.DNSSECValidated {
		t.Error("DNSSECValidated must be false")
	}
}

func TestDANEValidatedPasses(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTLSA("_25._tcp.mx.example.com", dnsx.TLSAResult{
		Found:  true,
		Secure: true,
		Records: []dnsx.TLSARecord{
			{Usage: UsageDANEEE, Selector: 1, MatchingType: 1, Certificate: "abcd"},
		},
	})
	resolver := dnsx.NewTestResolver(backend)

	got := CheckDANE(resolver, "mx.example.com", 25)
	if got.Result != DANEPass {
		t.Fatalf("expected pass, got %s (%s)", got.Result, got.Explanation)
	}
	if got.UsableRecords != 1 {
		t.Errorf("expected one usable record, got %d", got.UsableRecords)
	}
}

// PKIX usages are not applicable to SMTP DANE per RFC 7672.
func TestDANEPKIXOnlyIsPermError(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddTLSA("_25._tcp.mx.example.com", dnsx.TLSAResult{
		Found:  true,
		Secure: true,
		Records: []dnsx.TLSARecord{
			{Usage: UsagePKIXEE, Selector: 1, MatchingType: 1, Certificate: "abcd"},
		},
	})
	resolver := dnsx.NewTestResolver(backend)

	got := CheckDANE(resolver, "mx.example.com", 25)
	if got.Result != DANEPermError {
		t.Fatalf("expected permerror for PKIX-only records, got %s", got.Result)
	}
}

func TestDANENoRecordsIsNone(t *testing.T) {
	resolver := dnsx.NewTestResolver(dnsx.NewStaticBackend())

	got := CheckDANE(resolver, "mx.example.com", 25)
	if got.Result != DANENone {
		t.Fatalf("expected none, got %s", got.Result)
	}
}

// Partial TLSA deployment across MX hosts is a downgrade opportunity.
func TestDANEPartialDeploymentIsInsecure(t *testing.T) {
	backend := dnsx.NewStaticBackend()
	backend.AddMX("example.com", "mx1.example.com", "mx2.example.com")
	backend.AddTLSA("_25._tcp.mx1.example.com", dnsx.TLSAResult{
		Found: true, Secure: true,
		Records: []dnsx.TLSARecord{{Usage: UsageDANEEE, Selector: 1, MatchingType: 1, Certificate: "ab"}},
	})
	resolver := dnsx.NewTestResolver(backend)

	got := CheckDANEDomain(resolver, "example.com")
	if got.Result != DANEInsecure {
		t.Fatalf("expected insecure for partial deployment, got %s", got.Result)
	}
	if got.SecureHosts != 1 {
		t.Errorf("expected one secure host, got %d", got.SecureHosts)
	}
}

func TestDANEWithoutResolverIsTempError(t *testing.T) {
	if got := CheckDANE(nil, "mx.example.com", 25); got.Result != DANETempError {
		t.Fatalf("expected temperror without a resolver, got %s", got.Result)
	}
}

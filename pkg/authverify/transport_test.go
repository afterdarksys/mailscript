package authverify

import (
	"context"
	"strings"
	"testing"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

func TestTLSReportingPolicy(t *testing.T) {
	b := dnsx.NewStaticBackend().AddSecureTXT("_smtp._tls.example.com",
		"v=TLSRPTv1; rua=mailto:tls@example.com,https://reports.example.com/tls")
	got := CheckTLSReporting(dnsx.NewTestResolver(b), "example.com")
	if got.Result != "valid" || !got.DNSSEC || len(got.ReportURIs) != 2 {
		t.Fatalf("unexpected result: %+v", got)
	}
}

func TestMTASTSPolicy(t *testing.T) {
	b := dnsx.NewStaticBackend().AddSecureTXT("_mta-sts.example.com", "v=STSv1; id=20260731")
	fetch := func(_ context.Context, policyURL string) ([]byte, error) {
		if policyURL != "https://mta-sts.example.com/.well-known/mta-sts.txt" {
			t.Fatalf("unexpected URL %s", policyURL)
		}
		return []byte("version: STSv1\r\nmode: enforce\r\nmx: *.example.com\r\nmax_age: 86400\r\n"), nil
	}
	got := CheckMTASTS(dnsx.NewTestResolver(b), "example.com", fetch)
	if got.Result != "valid" || got.Mode != "enforce" || got.MaxAge != 86400 || !got.DNSSEC {
		t.Fatalf("unexpected result: %+v", got)
	}
	if !got.AllowsMX("mail.eu.example.com") || got.AllowsMX("example.com") {
		t.Fatalf("unexpected MX matching behavior: %+v", got)
	}
}

func TestMTASTSRejectsMissingMX(t *testing.T) {
	b := dnsx.NewStaticBackend().AddTXT("_mta-sts.example.com", "v=STSv1; id=x")
	got := CheckMTASTS(dnsx.NewTestResolver(b), "example.com", func(context.Context, string) ([]byte, error) {
		return []byte("version: STSv1\nmode: enforce\nmax_age: 1\n"), nil
	})
	if got.Result != "permerror" || !strings.Contains(got.Explanation, "mx") {
		t.Fatalf("unexpected result: %+v", got)
	}
}

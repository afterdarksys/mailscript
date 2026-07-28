package authverify

import (
	"strings"
	"testing"

	"github.com/afterdarksys/mailscript/pkg/dnsx"
)

func spfResolver(setup func(*dnsx.StaticBackend)) (*dnsx.Resolver, *dnsx.StaticBackend) {
	backend := dnsx.NewStaticBackend()
	if setup != nil {
		setup(backend)
	}
	return dnsx.NewTestResolver(backend), backend
}

func TestSPFPassOnIP4Mechanism(t *testing.T) {
	resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
		b.AddTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
	})

	got := VerifySPF(resolver, "192.0.2.10", "alice@example.com", "mail.example.com")
	if got.Result != SPFPass {
		t.Fatalf("expected pass, got %s (%s)", got.Result, got.Explanation)
	}
	if got.Domain != "example.com" {
		t.Errorf("expected domain example.com, got %q", got.Domain)
	}
}

func TestSPFFailOutsideNetwork(t *testing.T) {
	resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
		b.AddTXT("example.com", "v=spf1 ip4:192.0.2.0/24 -all")
	})

	got := VerifySPF(resolver, "198.51.100.7", "alice@example.com", "mail.example.com")
	if got.Result != SPFFail {
		t.Fatalf("expected fail for an address outside the network, got %s", got.Result)
	}
}

func TestSPFSoftfailAndNeutralQualifiers(t *testing.T) {
	cases := []struct {
		record string
		want   string
	}{
		{"v=spf1 ~all", SPFSoftfail},
		{"v=spf1 ?all", SPFNeutral},
		{"v=spf1 -all", SPFFail},
		{"v=spf1 +all", SPFPass},
	}

	for _, tc := range cases {
		resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
			b.AddTXT("example.com", tc.record)
		})
		got := VerifySPF(resolver, "198.51.100.7", "alice@example.com", "helo")
		if got.Result != tc.want {
			t.Errorf("record %q: expected %s, got %s", tc.record, tc.want, got.Result)
		}
	}
}

func TestSPFNoRecordIsNone(t *testing.T) {
	resolver, _ := spfResolver(nil)

	got := VerifySPF(resolver, "192.0.2.1", "alice@nosuch.example", "helo")
	if got.Result != SPFNone {
		t.Fatalf("expected none when no record is published, got %s", got.Result)
	}
}

// A domain publishing two SPF records is a permerror, because which one
// applies is undefined and an attacker could exploit parser disagreement.
func TestSPFMultipleRecordsIsPermError(t *testing.T) {
	resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
		b.AddTXT("example.com",
			"v=spf1 ip4:192.0.2.1 -all",
			"v=spf1 ip4:198.51.100.1 -all")
	})

	got := VerifySPF(resolver, "192.0.2.1", "alice@example.com", "helo")
	if got.Result != SPFPermError {
		t.Fatalf("expected permerror for duplicate records, got %s", got.Result)
	}
}

// The 10-lookup limit is what stops a hostile record turning one message into
// unbounded DNS traffic against third parties.
func TestSPFLookupLimitIsEnforced(t *testing.T) {
	resolver, backend := spfResolver(func(b *dnsx.StaticBackend) {
		// A chain of includes, each pointing at the next, well past the limit.
		b.AddTXT("example.com", "v=spf1 include:c1.example -all")
		for i := 1; i <= 30; i++ {
			name := "c" + itoa(i) + ".example"
			next := "c" + itoa(i+1) + ".example"
			b.AddTXT(name, "v=spf1 include:"+next+" -all")
		}
	})

	got := VerifySPF(resolver, "192.0.2.1", "alice@example.com", "helo")
	if got.Result != SPFPermError {
		t.Fatalf("expected permerror from the lookup limit, got %s (%s)", got.Result, got.Explanation)
	}
	if !strings.Contains(got.Explanation, "DNS-lookup limit") {
		t.Errorf("expected the explanation to cite the lookup limit, got %q", got.Explanation)
	}
	// The traversal must actually have stopped, not merely reported a limit.
	if backend.QueryCount() > 40 {
		t.Errorf("traversal did not stop: %d queries made", backend.QueryCount())
	}
}

// A redirect loop must terminate rather than recursing forever.
func TestSPFRedirectLoopTerminates(t *testing.T) {
	resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
		b.AddTXT("a.example", "v=spf1 redirect=b.example")
		b.AddTXT("b.example", "v=spf1 redirect=a.example")
	})

	got := VerifySPF(resolver, "192.0.2.1", "alice@a.example", "helo")
	if got.Result != SPFPermError {
		t.Fatalf("expected permerror from a redirect loop, got %s", got.Result)
	}
}

func TestSPFIncludeAndMXMechanisms(t *testing.T) {
	resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
		b.AddTXT("example.com", "v=spf1 include:sender.example mx -all")
		b.AddTXT("sender.example", "v=spf1 ip4:203.0.113.0/24 -all")
		b.AddMX("example.com", "mx1.example.com")
		b.AddHost("mx1.example.com", "192.0.2.25")
	})

	if got := VerifySPF(resolver, "203.0.113.5", "a@example.com", "h"); got.Result != SPFPass {
		t.Errorf("include should pass, got %s", got.Result)
	}
	if got := VerifySPF(resolver, "192.0.2.25", "a@example.com", "h"); got.Result != SPFPass {
		t.Errorf("mx should pass, got %s", got.Result)
	}
	if got := VerifySPF(resolver, "10.0.0.1", "a@example.com", "h"); got.Result != SPFFail {
		t.Errorf("unrelated address should fail, got %s", got.Result)
	}
}

// A null reverse path (a bounce) must be checked against the HELO identity.
func TestSPFNullSenderUsesHELO(t *testing.T) {
	resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
		b.AddTXT("relay.example", "v=spf1 ip4:192.0.2.1 -all")
	})

	got := VerifySPF(resolver, "192.0.2.1", "", "relay.example")
	if got.Result != SPFPass {
		t.Fatalf("expected the HELO identity to be checked, got %s (%s)", got.Result, got.Explanation)
	}
	if got.Domain != "relay.example" {
		t.Errorf("expected domain relay.example, got %q", got.Domain)
	}
}

func TestSPFRejectsMalformedInput(t *testing.T) {
	resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
		b.AddTXT("example.com", "v=spf1 ip4:not-an-address -all")
	})

	if got := VerifySPF(resolver, "192.0.2.1", "a@example.com", "h"); got.Result != SPFPermError {
		t.Errorf("expected permerror for a malformed ip4 term, got %s", got.Result)
	}

	// A non-IP client address cannot be evaluated at all.
	if got := VerifySPF(resolver, "definitely-not-an-ip", "a@example.com", "h"); got.Result != SPFPermError {
		t.Errorf("expected permerror for a non-IP client, got %s", got.Result)
	}
}

// With no resolver, SPF must report temperror rather than silently passing.
func TestSPFFailsClosedWithoutResolver(t *testing.T) {
	got := VerifySPF(nil, "192.0.2.1", "a@example.com", "h")
	if got.Result != SPFTempError {
		t.Fatalf("expected temperror without a resolver, got %s", got.Result)
	}
}

func TestSPFUnknownMechanismIsPermError(t *testing.T) {
	resolver, _ := spfResolver(func(b *dnsx.StaticBackend) {
		b.AddTXT("example.com", "v=spf1 frobnicate:xyz -all")
	})

	got := VerifySPF(resolver, "192.0.2.1", "a@example.com", "h")
	if got.Result != SPFPermError {
		t.Fatalf("expected permerror for an unknown mechanism, got %s", got.Result)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

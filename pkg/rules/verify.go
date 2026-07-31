package rules

import (
	"strings"

	"github.com/afterdarksys/mailscript/pkg/authverify"
	"go.starlark.net/starlark"
)

// RawHeaderPairs returns the message's fields as (name, rawValue) pairs in
// received order. DKIM canonicalisation depends on the exact bytes, so this
// reconstructs the value from the raw field text when it is available and
// falls back to the unfolded value otherwise.
func (m *MessageContext) RawHeaderPairs() [][2]string {
	pairs := make([][2]string, 0, len(m.HeaderList))
	for _, h := range m.HeaderList {
		if h.Name == "" {
			continue
		}

		value := h.Value
		if h.Raw != "" {
			// Recover everything after the first colon, preserving the
			// original folding and whitespace.
			if colon := strings.Index(h.Raw, ":"); colon >= 0 {
				value = h.Raw[colon+1:]
			}
		}
		pairs = append(pairs, [2]string{h.Name, value})
	}
	return pairs
}

// VerifyAuth runs SPF, DKIM, DMARC and optionally DANE against the message
// and caches the result on the context.
//
// Unlike AuthResults, which reads what an upstream MTA claimed, this derives
// every verdict from the message bytes and DNS. A forged
// Authentication-Results header has no influence on the outcome.
func (m *MessageContext) VerifyAuth(checkDANE bool) *authverify.Result {
	if m.Verified != nil {
		return m.Verified
	}

	body := m.RawBody
	if body == nil {
		body = []byte(m.Body)
	}

	m.Verified = authverify.Verify(m.Resolver, authverify.Input{
		Headers:    m.RawHeaderPairs(),
		Body:       body,
		ClientIP:   m.clientIP(),
		MailFrom:   m.envelopeSender(),
		HELO:       m.HELO,
		FromDomain: DomainOf(m.Get("From")),
		Now:        m.RefTime(),
		CheckDANE:  checkDANE,
	})
	return m.Verified
}

// clientIP returns the address SPF should be evaluated against: the one the
// transport reported, or the oldest public address in the Received chain.
func (m *MessageContext) clientIP() string {
	if m.SenderIP != "" {
		return m.SenderIP
	}
	hops := m.ReceivedChain()
	for i := len(hops) - 1; i >= 0; i-- {
		if ip := hops[i].FromIP; ip != "" && !IsPrivateIP(ip) {
			return ip
		}
	}
	return ""
}

// verifyBuiltins exposes real authentication verification to rule scripts.
func (e *scriptEnv) verifyBuiltins() starlark.StringDict {
	msg := e.msg

	// checkDANE is opt-in per call because it costs a DNS round trip per MX
	// host of the sender domain.
	verify := func(withDANE bool) *authverify.Result { return msg.VerifyAuth(withDANE) }

	return starlark.StringDict{
		"verify_auth": starlark.NewBuiltin("verify_auth",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				checkDANE := false
				if err := starlark.UnpackArgs("verify_auth", args, kwargs, "dane?", &checkDANE); err != nil {
					return nil, err
				}
				result := verify(checkDANE)

				out := dictOf(
					"authenticated", result.Authenticated,
					"disposition", result.Disposition(),
					"from_domain", result.FromDomain,
					"spf", result.SPF.Result,
					"spf_domain", result.SPF.Domain,
					"dkim", result.DKIM.Result,
					"dkim_domains", result.DKIM.PassingDomains,
					"dmarc", result.DMARC.Result,
					"arc", result.ARC.Result,
					"dmarc_aligned_spf", result.DMARC.SPFAligned,
					"dmarc_aligned_dkim", result.DMARC.DKIMAligned,
					"summary", result.Summary(),
					"warnings", result.Warnings(),
					"elapsed_ms", result.Elapsed.Milliseconds(),
				)
				if result.DMARC.Record != nil {
					_ = out.SetKey(starlark.String("dmarc_policy"), starlark.String(result.DMARC.Record.Policy))
					_ = out.SetKey(starlark.String("dmarc_pct"), starlark.MakeInt(result.DMARC.Record.Percent))
				}
				if result.DANE != nil {
					_ = out.SetKey(starlark.String("dane"), starlark.String(result.DANE.Result))
					_ = out.SetKey(starlark.String("dane_secure_hosts"), starlark.MakeInt(result.DANE.SecureHosts))
				}
				return out, nil
			}),

		"verify_spf":   nullaryStr("verify_spf", func() string { return verify(false).SPF.Result }),
		"verify_dkim":  nullaryStr("verify_dkim", func() string { return verify(false).DKIM.Result }),
		"verify_dmarc": nullaryStr("verify_dmarc", func() string { return verify(false).DMARC.Result }),
		"verify_arc":   nullaryStr("verify_arc", func() string { return verify(false).ARC.Result }),
		"verify_arc_details": nullary("verify_arc_details", func() starlark.Value {
			arc := verify(false).ARC
			sets := make([]starlark.Value, 0, len(arc.Sets))
			for _, set := range arc.Sets {
				sets = append(sets, dictOf(
					"instance", set.Instance,
					"domain", set.Domain,
					"selector", set.Selector,
					"cv", set.ChainValidation,
					"message_signature", set.MessageSignature,
					"seal", set.Seal,
					"explanation", set.Explanation,
				))
			}
			return dictOf("result", arc.Result, "sets", starlark.NewList(sets), "explanation", arc.Explanation)
		}),

		// is_verified is the check most policies want: the sender
		// cryptographically proved control of the From domain.
		"is_verified": nullaryBool("is_verified", func() bool { return verify(false).Authenticated }),

		"auth_disposition": nullaryStr("auth_disposition", func() string { return verify(false).Disposition() }),
		"auth_warnings":    nullaryList("auth_warnings", func() []string { return verify(false).Warnings() }),
		"auth_summary":     nullaryStr("auth_summary", func() string { return verify(false).Summary() }),

		"authentication_results": starlark.NewBuiltin("authentication_results",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var authserv string
				if err := starlark.UnpackArgs("authentication_results", args, kwargs, "authserv_id?", &authserv); err != nil {
					return nil, err
				}
				return starlark.String(verify(false).AuthenticationResults(authserv)), nil
			}),

		// verify_dkim_details exposes the per-signature outcome, including
		// the l= body-truncation flag that a bare pass would hide.
		"verify_dkim_details": nullary("verify_dkim_details", func() starlark.Value {
			result := verify(false)
			values := make([]starlark.Value, 0, len(result.DKIM.Signatures))
			for _, sig := range result.DKIM.Signatures {
				values = append(values, dictOf(
					"result", sig.Result,
					"domain", sig.Domain,
					"selector", sig.Selector,
					"algorithm", sig.Algorithm,
					"key_bits", sig.KeyBits,
					"headers_signed", sig.HeadersSigned,
					"body_truncated", sig.BodyTruncated,
					"signed_bytes", sig.SignedBytes,
					"body_bytes", sig.BodyBytes,
					"expired", sig.Expired,
					"explanation", sig.Explanation,
				))
			}
			return starlark.NewList(values)
		}),

		"verify_spf_details": nullary("verify_spf_details", func() starlark.Value {
			spf := verify(false).SPF
			return dictOf(
				"result", spf.Result,
				"domain", spf.Domain,
				"sender", spf.Sender,
				"client_ip", spf.ClientIP,
				"mechanism", spf.Mechanism,
				"lookups", spf.Lookups,
				"record", spf.Record,
				"explanation", spf.Explanation,
			)
		}),

		"verify_dmarc_details": nullary("verify_dmarc_details", func() starlark.Value {
			dmarc := verify(false).DMARC
			out := dictOf(
				"result", dmarc.Result,
				"disposition", dmarc.Disposition,
				"from_domain", dmarc.FromDomain,
				"spf_aligned", dmarc.SPFAligned,
				"dkim_aligned", dmarc.DKIMAligned,
				"aligned_dkim_domains", dmarc.AlignedDKIMDomains,
				"explanation", dmarc.Explanation,
			)
			if dmarc.Record != nil {
				_ = out.SetKey(starlark.String("policy"), starlark.String(dmarc.Record.Policy))
				_ = out.SetKey(starlark.String("subdomain_policy"), starlark.String(dmarc.Record.SubdomainPolicy))
				_ = out.SetKey(starlark.String("pct"), starlark.MakeInt(dmarc.Record.Percent))
				_ = out.SetKey(starlark.String("adkim"), starlark.String(dmarc.Record.ADKIM))
				_ = out.SetKey(starlark.String("aspf"), starlark.String(dmarc.Record.ASPF))
				_ = out.SetKey(starlark.String("record_domain"), starlark.String(dmarc.Record.Domain))
				_ = out.SetKey(starlark.String("from_org_domain"), starlark.Bool(dmarc.Record.Organizational))
			}
			return out
		}),

		"verify_dane": starlark.NewBuiltin("verify_dane",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var domain string
				if err := starlark.UnpackArgs("verify_dane", args, kwargs, "domain?", &domain); err != nil {
					return nil, err
				}
				if domain == "" {
					domain = DomainOf(msg.Get("From"))
				}

				dane := authverify.CheckDANEDomain(msg.Resolver, domain)
				hosts := make([]starlark.Value, 0, len(dane.Hosts))
				for _, h := range dane.Hosts {
					records := make([]string, 0, len(h.Records))
					for _, r := range h.Records {
						records = append(records, authverify.DescribeTLSA(r))
					}
					hosts = append(hosts, dictOf(
						"host", h.Host,
						"result", h.Result,
						"tlsa_found", h.TLSAFound,
						"dnssec_validated", h.DNSSECValidated,
						"usable_records", h.UsableRecords,
						"records", records,
						"explanation", h.Explanation,
					))
				}

				return dictOf(
					"result", dane.Result,
					"domain", dane.Domain,
					"secure_hosts", dane.SecureHosts,
					"hosts", starlark.NewList(hosts),
					"explanation", dane.Explanation,
				), nil
			}),

		"check_tlsrpt": starlark.NewBuiltin("check_tlsrpt",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var domain string
				if err := starlark.UnpackArgs("check_tlsrpt", args, kwargs, "domain?", &domain); err != nil {
					return nil, err
				}
				if domain == "" {
					domain = DomainOf(msg.Get("From"))
				}
				policy := authverify.CheckTLSReporting(msg.Resolver, domain)
				return dictOf(
					"result", policy.Result,
					"domain", policy.Domain,
					"record", policy.Record,
					"report_uris", policy.ReportURIs,
					"dnssec_validated", policy.DNSSEC,
					"explanation", policy.Explanation,
				), nil
			}),

		"check_mta_sts": starlark.NewBuiltin("check_mta_sts",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var domain string
				if err := starlark.UnpackArgs("check_mta_sts", args, kwargs, "domain?", &domain); err != nil {
					return nil, err
				}
				if domain == "" {
					domain = DomainOf(msg.Get("From"))
				}
				policy := authverify.CheckMTASTS(msg.Resolver, domain, nil)
				return dictOf(
					"result", policy.Result,
					"domain", policy.Domain,
					"id", policy.ID,
					"mode", policy.Mode,
					"mx", policy.MX,
					"max_age", policy.MaxAge,
					"dnssec_validated", policy.DNSSEC,
					"explanation", policy.Explanation,
				), nil
			}),

		// -- Reported (untrusted) results --------------------------------
		//
		// These read what an upstream MTA claimed. They are only meaningful
		// when auth_results_trusted() is true.

		"auth_results_trusted": nullaryBool("auth_results_trusted", func() bool {
			return msg.AuthResults().Trusted
		}),

		"untrusted_authservs": nullaryList("untrusted_authservs", func() []string {
			return msg.AuthResults().UntrustedAuthServs
		}),

		// forged_auth_results reports the case worth alerting on: the message
		// carries an Authentication-Results header claiming a pass, from an
		// authority this deployment does not operate.
		"forged_auth_results": nullaryBool("forged_auth_results", func() bool {
			ar := msg.AuthResults()
			if !ar.Present || ar.Trusted || len(ar.UntrustedAuthServs) == 0 {
				return false
			}
			return ar.SPF == "pass" || ar.DKIM == "pass" || ar.DMARC == "pass"
		}),
	}
}

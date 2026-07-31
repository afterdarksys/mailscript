package rules

import (
	"fmt"
	"net/mail"
	"strings"
	"time"

	"go.starlark.net/starlark"
)

// mailParseDate parses an RFC 5322 date field.
func mailParseDate(raw string) (time.Time, error) {
	return mail.ParseDate(raw)
}

// ---------------------------------------------------------------------------
// Header validation
// ---------------------------------------------------------------------------

func (e *scriptEnv) validationBuiltins() starlark.StringDict {
	msg := e.msg

	findingValue := func(f Finding) starlark.Value {
		return dictOf(
			"code", f.Code,
			"severity", f.Severity,
			"header", f.Header,
			"message", f.Message,
			"score", f.Score,
		)
	}

	return starlark.StringDict{
		// validate_headers returns every finding as a dict, most severe first.
		"validate_headers": starlark.NewBuiltin("validate_headers",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var minSeverity string
				if err := starlark.UnpackArgs("validate_headers", args, kwargs, "min_severity?", &minSeverity); err != nil {
					return nil, err
				}
				threshold := severityRank(minSeverity)

				var values []starlark.Value
				for _, f := range msg.ValidateHeaders() {
					if severityRank(f.Severity) < threshold {
						continue
					}
					values = append(values, findingValue(f))
				}
				return starlark.NewList(values), nil
			}),

		"validation_codes": nullaryList("validation_codes", func() []string {
			findings := msg.ValidateHeaders()
			out := make([]string, 0, len(findings))
			for _, f := range findings {
				out = append(out, f.Code)
			}
			return out
		}),

		"has_finding": unaryBool("has_finding", "code", func(code string) bool {
			for _, f := range msg.ValidateHeaders() {
				if f.Code == code {
					return true
				}
			}
			for _, result := range msg.AnalyzerResults {
				for _, finding := range result.Findings {
					if finding.Code == code {
						return true
					}
				}
			}
			return false
		}),

		"finding_count": starlark.NewBuiltin("finding_count",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var minSeverity string
				if err := starlark.UnpackArgs("finding_count", args, kwargs, "min_severity?", &minSeverity); err != nil {
					return nil, err
				}
				threshold := severityRank(minSeverity)
				count := 0
				for _, f := range msg.ValidateHeaders() {
					if severityRank(f.Severity) >= threshold {
						count++
					}
				}
				return starlark.MakeInt(count), nil
			}),

		// max_severity returns the highest severity observed, or "" when the
		// message is clean.
		"max_severity": nullaryStr("max_severity", func() string {
			findings := msg.ValidateHeaders()
			if len(findings) == 0 {
				return ""
			}
			return findings[0].Severity // ValidateHeaders sorts descending
		}),

		// validation_score sums the suggested score of every finding, giving
		// a single number a policy can threshold on.
		"validation_score": nullaryFloat("validation_score", func() float64 {
			total := 0.0
			for _, f := range msg.ValidateHeaders() {
				total += f.Score
			}
			return total
		}),

		// apply_validation_score folds the validation total into the running
		// message score, recording each finding as a reason.
		"apply_validation_score": starlark.NewBuiltin("apply_validation_score",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var minSeverity string
				if err := starlark.UnpackArgs("apply_validation_score", args, kwargs, "min_severity?", &minSeverity); err != nil {
					return nil, err
				}
				threshold := severityRank(minSeverity)
				for _, f := range msg.ValidateHeaders() {
					if severityRank(f.Severity) < threshold {
						continue
					}
					msg.AddScore(f.Score, f.Code+": "+f.Message)
				}
				return starlark.Float(msg.Score), nil
			}),

		"is_valid_address": unaryBool("is_valid_address", "value", func(v string) bool {
			_, err := mail.ParseAddress(v)
			return err == nil
		}),

		"is_valid_message_id": unaryBool("is_valid_message_id", "value", func(v string) bool {
			v = strings.TrimSpace(v)
			if !strings.HasPrefix(v, "<") || !strings.HasSuffix(v, ">") || len(v) < 4 {
				return false
			}
			inner := v[1 : len(v)-1]
			at := strings.LastIndex(inner, "@")
			return at > 0 && at < len(inner)-1
		}),
	}
}

// ---------------------------------------------------------------------------
// Identity, addresses and domains
// ---------------------------------------------------------------------------

func (e *scriptEnv) identityBuiltins() starlark.StringDict {
	msg := e.msg

	addressValue := func(a Address) starlark.Value {
		return dictOf(
			"name", a.Name,
			"address", a.Address,
			"local", a.Local,
			"domain", a.Domain,
			"registered_domain", RegisteredDomain(a.Domain),
			"valid", a.Valid,
		)
	}

	addressListValue := func(field string) starlark.Value {
		parsed := ParseAddressList(msg.Get(field))
		values := make([]starlark.Value, 0, len(parsed))
		for _, a := range parsed {
			values = append(values, addressValue(a))
		}
		return starlark.NewList(values)
	}

	return starlark.StringDict{
		"parse_address": unary("parse_address", "value", func(v string) starlark.Value {
			return addressValue(ParseAddress(v))
		}),

		"parse_address_list": unary("parse_address_list", "value", func(v string) starlark.Value {
			parsed := ParseAddressList(v)
			values := make([]starlark.Value, 0, len(parsed))
			for _, a := range parsed {
				values = append(values, addressValue(a))
			}
			return starlark.NewList(values)
		}),

		"from_address":      nullaryStr("from_address", func() string { return ParseAddress(msg.Get("From")).Address }),
		"from_domain":       nullaryStr("from_domain", func() string { return DomainOf(msg.Get("From")) }),
		"from_local":        nullaryStr("from_local", func() string { return ParseAddress(msg.Get("From")).Local }),
		"from_display_name": nullaryStr("from_display_name", func() string { return ParseAddress(msg.Get("From")).Name }),
		"reply_to_domain":   nullaryStr("reply_to_domain", func() string { return DomainOf(msg.Get("Reply-To")) }),
		"sender_domain":     nullaryStr("sender_domain", func() string { return DomainOf(msg.Get("Sender")) }),

		"get_sender_domain": nullaryStr("get_sender_domain", func() string {
			if msg.SenderDomain != "" {
				return msg.SenderDomain
			}
			return DomainOf(msg.Get("From"))
		}),

		"envelope_from": nullaryStr("envelope_from", func() string { return msg.envelopeSender() }),
		"envelope_from_domain": nullaryStr("envelope_from_domain", func() string {
			return DomainOf(msg.envelopeSender())
		}),
		"envelope_to": nullaryList("envelope_to", func() []string {
			if len(msg.EnvelopeTo) > 0 {
				return msg.EnvelopeTo
			}
			if v := msg.Get("X-Envelope-To"); v != "" {
				parts := strings.Split(v, ",")
				for i := range parts {
					parts[i] = strings.TrimSpace(parts[i])
				}
				return parts
			}
			return nil
		}),

		"to_addresses": nullary("to_addresses", func() starlark.Value { return addressListValue("To") }),
		"cc_addresses": nullary("cc_addresses", func() starlark.Value { return addressListValue("Cc") }),
		"recipient_count": nullaryInt("recipient_count", func() int {
			return len(ParseAddressList(msg.Get("To"))) + len(ParseAddressList(msg.Get("Cc")))
		}),

		"registered_domain": unaryStr("registered_domain", "host", RegisteredDomain),
		"public_suffix":     unaryStr("public_suffix", "host", PublicSuffix),
		"to_unicode_domain": unaryStr("to_unicode_domain", "host", ToUnicodeDomain),
		"to_ascii_domain":   unaryStr("to_ascii_domain", "host", ToASCIIDomain),
		"skeleton":          unaryStr("skeleton", "value", Skeleton),

		"same_org_domain": binary("same_org_domain", "a", "b", func(a, b string) (starlark.Value, error) {
			return starlark.Bool(SameOrgDomain(a, b)), nil
		}),

		"is_subdomain_of": binary("is_subdomain_of", "host", "parent", func(host, parent string) (starlark.Value, error) {
			return starlark.Bool(IsSubdomainOf(host, parent)), nil
		}),

		"looks_like": binary("looks_like", "candidate", "target", func(candidate, target string) (starlark.Value, error) {
			return starlark.Bool(LooksLike(candidate, target)), nil
		}),

		// looks_like_any is the practical form: check the From domain against
		// a watchlist of brands being impersonated.
		"looks_like_any": starlark.NewBuiltin("looks_like_any",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var candidate string
				var targets starlark.Value
				if err := starlark.UnpackArgs("looks_like_any", args, kwargs, "candidate", &candidate, "targets", &targets); err != nil {
					return nil, err
				}
				list, err := stringsFromValue(targets)
				if err != nil {
					return nil, fmt.Errorf("looks_like_any: %w", err)
				}
				for _, target := range list {
					if LooksLike(candidate, target) {
						return starlark.String(target), nil
					}
				}
				return starlark.String(""), nil
			}),

		"is_mixed_script": unaryBool("is_mixed_script", "value", IsMixedScript),
		"unicode_scripts": unaryList("unicode_scripts", "value", ScriptsIn),

		"display_name_spoofed": nullaryBool("display_name_spoofed", func() bool {
			from := ParseAddress(msg.Get("From"))
			claimed := extractAddressFromText(from.Name)
			return claimed != "" && !strings.EqualFold(claimed, from.Address)
		}),
	}
}

// ---------------------------------------------------------------------------
// Authentication results
// ---------------------------------------------------------------------------

func (e *scriptEnv) authBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"auth_results": nullary("auth_results", func() starlark.Value {
			ar := msg.AuthResults()
			return dictOf(
				"present", ar.Present,
				"authserv_id", ar.AuthServID,
				"spf", ar.SPF,
				"spf_domain", ar.SPFDomain,
				"dkim", ar.DKIM,
				"dkim_domains", ar.DKIMDomains,
				"dkim_all_domains", ar.DKIMAllDomains,
				"dmarc", ar.DMARC,
				"dmarc_policy", ar.DMARCPolicy,
				"arc", ar.ARC,
				"signed", ar.Signed,
			)
		}),

		"spf_result":   nullaryStr("spf_result", func() string { return msg.AuthResults().SPF }),
		"dkim_result":  nullaryStr("dkim_result", func() string { return msg.AuthResults().DKIM }),
		"dmarc_result": nullaryStr("dmarc_result", func() string { return msg.AuthResults().DMARC }),
		"arc_result":   nullaryStr("arc_result", func() string { return msg.AuthResults().ARC }),
		"spf_domain":   nullaryStr("spf_domain", func() string { return msg.AuthResults().SPFDomain }),
		"dkim_domains": nullaryList("dkim_domains", func() []string { return msg.AuthResults().DKIMDomains }),

		"has_auth_results":   nullaryBool("has_auth_results", func() bool { return msg.AuthResults().Present }),
		"has_dkim_signature": nullaryBool("has_dkim_signature", func() bool { return msg.AuthResults().Signed }),
		"dmarc_pass":         nullaryBool("dmarc_pass", msg.DMARCPass),
		"dmarc_policy":       nullaryStr("dmarc_policy", func() string { return msg.AuthResults().DMARCPolicy }),

		"spf_aligned": starlark.NewBuiltin("spf_aligned",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				strict := false
				if err := starlark.UnpackArgs("spf_aligned", args, kwargs, "strict?", &strict); err != nil {
					return nil, err
				}
				return starlark.Bool(msg.SPFAligned(strict)), nil
			}),

		"dkim_aligned": starlark.NewBuiltin("dkim_aligned",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				strict := false
				if err := starlark.UnpackArgs("dkim_aligned", args, kwargs, "strict?", &strict); err != nil {
					return nil, err
				}
				return starlark.Bool(msg.DKIMAligned(strict)), nil
			}),

		// is_authenticated is the single check most policies actually want:
		// the sender proved control of the From domain.
		"is_authenticated": nullaryBool("is_authenticated", func() bool {
			return msg.DMARCPass()
		}),
	}
}

// ---------------------------------------------------------------------------
// Received chain
// ---------------------------------------------------------------------------

func (e *scriptEnv) receivedBuiltins() starlark.StringDict {
	msg := e.msg

	hopValue := func(h ReceivedHop) starlark.Value {
		var ts starlark.Value = starlark.None
		if h.HasTimestamp {
			ts = starlark.String(h.Timestamp.UTC().Format(time.RFC3339))
		}
		return dictOf(
			"index", h.Index,
			"from", h.From,
			"from_ip", h.FromIP,
			"by", h.By,
			"with", h.With,
			"id", h.ID,
			"for", h.For,
			"timestamp", ts,
			"raw", h.Raw,
		)
	}

	return starlark.StringDict{
		"received_chain": nullary("received_chain", func() starlark.Value {
			hops := msg.ReceivedChain()
			values := make([]starlark.Value, 0, len(hops))
			for _, h := range hops {
				values = append(values, hopValue(h))
			}
			return starlark.NewList(values)
		}),

		"received_count": nullaryInt("received_count", func() int { return len(msg.ReceivedChain()) }),

		"received_hop": starlark.NewBuiltin("received_hop",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var level int
				if err := starlark.UnpackArgs("received_hop", args, kwargs, "level", &level); err != nil {
					return nil, err
				}
				hops := msg.ReceivedChain()
				if level < 0 || level >= len(hops) {
					return starlark.None, nil
				}
				return hopValue(hops[level]), nil
			}),

		"check_received_header": starlark.NewBuiltin("check_received_header",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var level int
				if err := starlark.UnpackArgs("check_received_header", args, kwargs, "level", &level); err != nil {
					return nil, err
				}
				headers := msg.GetAll("Received")
				if level >= 0 && level < len(headers) {
					return starlark.String(headers[level]), nil
				}
				return starlark.String(""), nil
			}),

		"get_received_headers": nullaryList("get_received_headers", func() []string {
			return msg.GetAll("Received")
		}),

		// origin_ip returns the address the message entered the visible path
		// from, which is the one worth checking against a blocklist.
		"origin_ip": nullaryStr("origin_ip", func() string {
			if msg.SenderIP != "" {
				return msg.SenderIP
			}
			hops := msg.ReceivedChain()
			for i := len(hops) - 1; i >= 0; i-- {
				if ip := hops[i].FromIP; ip != "" && !IsPrivateIP(ip) {
					return ip
				}
			}
			for i := len(hops) - 1; i >= 0; i-- {
				if hops[i].FromIP != "" {
					return hops[i].FromIP
				}
			}
			return ""
		}),

		"get_sender_ip": nullaryStr("get_sender_ip", func() string { return msg.SenderIP }),
		"is_private_ip": unaryBool("is_private_ip", "ip", IsPrivateIP),
		"hop_ips": nullaryList("hop_ips", func() []string {
			var out []string
			for _, h := range msg.ReceivedChain() {
				if h.FromIP != "" {
					out = append(out, h.FromIP)
				}
			}
			return out
		}),
	}
}

// ---------------------------------------------------------------------------
// Content and URLs
// ---------------------------------------------------------------------------

func (e *scriptEnv) contentBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"get_body":      nullaryStr("get_body", func() string { return msg.Body }),
		"get_text_body": nullaryStr("get_text_body", func() string { return msg.TextBody }),
		"get_html_body": nullaryStr("get_html_body", func() string { return msg.HTMLBody }),
		"search_text":   nullaryStr("search_text", msg.SearchText),
		"html_to_text":  nullaryStr("html_to_text", msg.HTMLToText),
		"has_html":      nullaryBool("has_html", func() bool { return msg.HTMLBody != "" }),
		"has_plain":     nullaryBool("has_plain", func() bool { return strings.TrimSpace(msg.TextBody) != "" }),

		"html_text_ratio": nullaryFloat("html_text_ratio", msg.HTMLTextRatio),

		"mime_parts": nullary("mime_parts", func() starlark.Value {
			values := make([]starlark.Value, 0, len(msg.Parts))
			for _, p := range msg.Parts {
				values = append(values, dictOf(
					"content_type", p.ContentType,
					"charset", p.Charset,
					"disposition", p.Disposition,
					"filename", p.Filename,
					"size", p.Size,
					"depth", p.Depth,
				))
			}
			return starlark.NewList(values)
		}),

		"part_count": nullaryInt("part_count", func() int { return len(msg.Parts) }),

		"has_content_type": unaryBool("has_content_type", "media_type", func(want string) bool {
			want = strings.ToLower(want)
			for _, p := range msg.Parts {
				if strings.EqualFold(p.ContentType, want) {
					return true
				}
			}
			return false
		}),

		"get_urls":        nullaryList("get_urls", msg.URLs),
		"get_url_domains": nullaryList("get_url_domains", msg.URLDomains),
		"url_count":       nullaryInt("url_count", func() int { return len(msg.URLs()) }),

		"has_url_shortener": nullaryBool("has_url_shortener", msg.HasURLShortener),

		"url_display_mismatches": nullary("url_display_mismatches", func() starlark.Value {
			mismatches := msg.URLDisplayMismatches()
			values := make([]starlark.Value, 0, len(mismatches))
			for _, m := range mismatches {
				values = append(values, dictOf(
					"href", m.Href,
					"display_text", m.DisplayText,
					"href_host", m.HrefHost,
					"display_host", m.DisplayHost,
				))
			}
			return starlark.NewList(values)
		}),

		"has_url_display_mismatch": nullaryBool("has_url_display_mismatch", func() bool {
			return len(msg.URLDisplayMismatches()) > 0
		}),

		"tracking_pixel_count": nullaryInt("tracking_pixel_count", msg.TrackingPixelCount),
		"has_tracking_pixel":   nullaryBool("has_tracking_pixel", func() bool { return msg.TrackingPixelCount() > 0 }),

		// url_domain_matches_from checks whether the links agree with the
		// sender, which they usually do for legitimate mail.
		"url_domains_off_brand": nullaryList("url_domains_off_brand", func() []string {
			from := DomainOf(msg.Get("From"))
			if from == "" {
				return nil
			}
			var out []string
			for _, host := range msg.URLDomains() {
				if !SameOrgDomain(host, from) {
					out = append(out, host)
				}
			}
			return out
		}),

		"entropy":          unaryFloat("entropy", "text", Entropy),
		"uppercase_ratio":  unaryFloat("uppercase_ratio", "text", UppercaseRatio),
		"non_ascii_ratio":  unaryFloat("non_ascii_ratio", "text", NonASCIIRatio),
		"body_entropy":     nullaryFloat("body_entropy", func() float64 { return Entropy(msg.SearchText()) }),
		"subject_shouting": nullaryBool("subject_shouting", func() bool { return UppercaseRatio(msg.Get("Subject")) > 0.6 }),
	}
}

// ---------------------------------------------------------------------------
// Attachments
// ---------------------------------------------------------------------------

func (e *scriptEnv) attachmentBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"get_attachments": nullary("get_attachments", func() starlark.Value {
			values := make([]starlark.Value, 0, len(msg.Attachments))
			for _, a := range msg.Attachments {
				values = append(values, dictOf(
					"filename", a.Filename,
					"extension", FileExtension(a.Filename),
					"content_type", a.ContentType,
					"disposition", a.Disposition,
					"size", a.Size,
					"sha256", a.SHA256,
					"inline", a.IsInline,
				))
			}
			return starlark.NewList(values)
		}),

		"attachment_count": nullaryInt("attachment_count", func() int { return len(msg.Attachments) }),
		"has_attachment":   nullaryBool("has_attachment", func() bool { return len(msg.Attachments) > 0 }),

		"attachment_names": nullaryList("attachment_names", func() []string {
			out := make([]string, 0, len(msg.Attachments))
			for _, a := range msg.Attachments {
				out = append(out, a.Filename)
			}
			return out
		}),

		"total_attachment_size": nullary("total_attachment_size", func() starlark.Value {
			var total int64
			for _, a := range msg.Attachments {
				total += a.Size
			}
			return starlark.MakeInt64(total)
		}),

		"has_attachment_ext": starlark.NewBuiltin("has_attachment_ext",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var extensions starlark.Value
				if err := starlark.UnpackArgs("has_attachment_ext", args, kwargs, "extensions", &extensions); err != nil {
					return nil, err
				}
				list, err := stringsFromValue(extensions)
				if err != nil {
					return nil, fmt.Errorf("has_attachment_ext: %w", err)
				}
				want := make(map[string]bool, len(list))
				for _, ext := range list {
					want[strings.ToLower(strings.TrimPrefix(ext, "."))] = true
				}
				for _, a := range msg.Attachments {
					if want[FileExtension(a.Filename)] {
						return starlark.Bool(true), nil
					}
				}
				return starlark.Bool(false), nil
			}),

		"has_executable_attachment": nullaryBool("has_executable_attachment", msg.HasExecutableAttachment),
		"has_macro_attachment":      nullaryBool("has_macro_attachment", msg.HasMacroAttachment),
		"has_archive_attachment":    nullaryBool("has_archive_attachment", msg.HasArchiveAttachment),

		"double_extension_attachments": nullaryList("double_extension_attachments", msg.DoubleExtensionAttachments),
		"rtl_override_attachments":     nullaryList("rtl_override_attachments", msg.RTLOverrideAttachments),

		"attachment_hashes": nullaryList("attachment_hashes", func() []string {
			out := make([]string, 0, len(msg.Attachments))
			for _, a := range msg.Attachments {
				out = append(out, a.SHA256)
			}
			return out
		}),
	}
}

// ---------------------------------------------------------------------------
// Human versus machine
// ---------------------------------------------------------------------------

func (e *scriptEnv) humanBuiltins() starlark.StringDict {
	msg := e.msg
	return starlark.StringDict{
		"human_score":  nullaryFloat("human_score", func() float64 { return msg.AssessHuman().Score }),
		"sender_class": nullaryStr("sender_class", func() string { return msg.AssessHuman().Class }),

		"is_human":     nullaryBool("is_human", msg.IsHuman),
		"is_automated": nullaryBool("is_automated", msg.IsAutomated),
		"is_bulk":      nullaryBool("is_bulk", msg.IsBulk),
		"is_list_mail": nullaryBool("is_list_mail", msg.isListMail),

		"is_transactional": nullaryBool("is_transactional", func() bool {
			return msg.AssessHuman().Class == ClassTransactional
		}),

		"human_reasons": nullaryList("human_reasons", func() []string {
			return msg.AssessHuman().Reasons
		}),

		"human_signals": nullary("human_signals", func() starlark.Value {
			assessment := msg.AssessHuman()
			values := make([]starlark.Value, 0, len(assessment.Signals))
			for _, s := range assessment.Signals {
				values = append(values, dictOf(
					"name", s.Name,
					"weight", s.Weight,
					"detail", s.Detail,
				))
			}
			return starlark.NewList(values)
		}),

		"has_human_signal": unaryBool("has_human_signal", "name", func(name string) bool {
			for _, s := range msg.AssessHuman().Signals {
				if s.Name == name {
					return true
				}
			}
			return false
		}),

		"is_threaded": nullaryBool("is_threaded", func() bool {
			return msg.Has("In-Reply-To") || msg.Has("References")
		}),

		"is_auto_submitted": nullaryBool("is_auto_submitted", func() bool {
			v := strings.ToLower(strings.TrimSpace(msg.Get("Auto-Submitted")))
			return v != "" && v != "no"
		}),

		"is_noreply_sender": nullaryBool("is_noreply_sender", func() bool {
			return noReplyPattern.MatchString(ParseAddress(msg.Get("From")).Local)
		}),

		"has_unsubscribe": nullaryBool("has_unsubscribe", func() bool {
			return msg.Has("List-Unsubscribe")
		}),

		"ai_generated_score": nullaryFloat("ai_generated_score", func() float64 {
			return msg.AssessAI().Score
		}),
		"ai_generated_class": nullaryStr("ai_generated_class", func() string {
			return msg.AssessAI().Class
		}),
		"ai_generation_reasons": nullaryList("ai_generation_reasons", func() []string {
			return msg.AssessAI().Reasons
		}),
		"is_ai_generated": starlark.NewBuiltin("is_ai_generated",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var rawThreshold starlark.Value = starlark.Float(70)
				if err := starlark.UnpackArgs("is_ai_generated", args, kwargs, "threshold?", &rawThreshold); err != nil {
					return nil, err
				}
				threshold := 70.0
				switch value := rawThreshold.(type) {
				case starlark.Float:
					threshold = float64(value)
				case starlark.Int:
					integer, ok := value.Int64()
					if !ok {
						return nil, fmt.Errorf("is_ai_generated: threshold is out of range")
					}
					threshold = float64(integer)
				default:
					return nil, fmt.Errorf("is_ai_generated: threshold must be a number")
				}
				return starlark.Bool(msg.AssessAI().Score >= threshold), nil
			}),
	}
}

// ---------------------------------------------------------------------------
// DNS and blocklists
//
// Every builtin here degrades to a header-only answer when no resolver is
// configured, so a rule written for a gateway with DNS still runs in the
// offline test harness.
// ---------------------------------------------------------------------------

func (e *scriptEnv) networkBuiltins() starlark.StringDict {
	msg := e.msg

	return starlark.StringDict{
		"dns_available": nullaryBool("dns_available", func() bool { return msg.Resolver.Enabled() }),

		"dnssec_txt": unary("dnssec_txt", "name", func(name string) starlark.Value {
			answer := msg.Resolver.LookupTXTAuthenticated(name)
			return dictOf(
				"name", answer.Name,
				"records", answer.Records,
				"found", answer.Found,
				"dnssec_validated", answer.Secure,
				"error", answer.Error,
			)
		}),

		"dns_check": unaryBool("dns_check", "domain", func(domain string) bool {
			if !msg.Resolver.Enabled() {
				return msg.DNSResolved
			}
			return len(msg.Resolver.LookupHost(domain)) > 0 || msg.Resolver.HasMX(domain)
		}),

		"dns_resolution": unaryStr("dns_resolution", "domain", func(domain string) string {
			if !msg.Resolver.Enabled() {
				return msg.SenderIP
			}
			if addrs := msg.Resolver.LookupHost(domain); len(addrs) > 0 {
				return addrs[0]
			}
			return ""
		}),

		"dns_a":   unaryList("dns_a", "domain", func(d string) []string { return msg.Resolver.LookupHost(d) }),
		"dns_txt": unaryList("dns_txt", "domain", func(d string) []string { return msg.Resolver.LookupTXT(d) }),
		"dns_ptr": unaryList("dns_ptr", "ip", func(ip string) []string { return msg.Resolver.LookupPTR(ip) }),

		"get_mx_records": unaryList("get_mx_records", "domain", func(domain string) []string {
			if !msg.Resolver.Enabled() {
				return msg.MXRecords
			}
			return msg.Resolver.LookupMX(domain)
		}),

		"valid_mx": unaryBool("valid_mx", "domain", func(domain string) bool {
			if !msg.Resolver.Enabled() {
				return len(msg.MXRecords) > 0
			}
			return msg.Resolver.HasMX(domain)
		}),

		"is_mx_ipv4": unaryBool("is_mx_ipv4", "domain", func(domain string) bool {
			return msg.mxHasFamily(domain, false)
		}),
		"is_mx_ipv6": unaryBool("is_mx_ipv6", "domain", func(domain string) bool {
			return msg.mxHasFamily(domain, true)
		}),

		"domain_resolution": binaryDomainResolution(msg),

		"rbl_check": starlark.NewBuiltin("rbl_check",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var ip, zone string
				if err := starlark.UnpackArgs("rbl_check", args, kwargs, "ip", &ip, "rbl_server?", &zone); err != nil {
					return nil, err
				}
				msg.Actions = append(msg.Actions, fmt.Sprintf("rbl_check:%s:%s", ip, zone))

				if !msg.Resolver.Enabled() {
					return starlark.Bool(msg.RBLListed), nil
				}
				if zone != "" {
					return starlark.Bool(msg.Resolver.CheckRBL(ip, zone).Listed), nil
				}
				listed, _ := msg.Resolver.CheckRBLs(ip)
				return starlark.Bool(listed), nil
			}),

		"rbl_lookup": starlark.NewBuiltin("rbl_lookup",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var ip, zone string
				if err := starlark.UnpackArgs("rbl_lookup", args, kwargs, "ip", &ip, "rbl_server?", &zone); err != nil {
					return nil, err
				}
				if !msg.Resolver.Enabled() {
					return starlark.NewList(nil), nil
				}

				var results []RBLResult
				if zone != "" {
					results = []RBLResult{msg.Resolver.CheckRBL(ip, zone)}
				} else {
					_, results = msg.Resolver.CheckRBLs(ip)
				}

				values := make([]starlark.Value, 0, len(results))
				for _, r := range results {
					values = append(values, dictOf(
						"zone", r.Zone,
						"listed", r.Listed,
						"codes", r.Codes,
						"comment", r.Comment,
					))
				}
				return starlark.NewList(values), nil
			}),

		"get_rbl_status": nullary("get_rbl_status", func() starlark.Value {
			return dictOf("listed", msg.RBLListed, "rbl_name", msg.RBLName)
		}),

		"mx_in_rbl": starlark.NewBuiltin("mx_in_rbl",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var domain, zone string
				if err := starlark.UnpackArgs("mx_in_rbl", args, kwargs, "domain", &domain, "rbl_server?", &zone); err != nil {
					return nil, err
				}
				msg.Actions = append(msg.Actions, fmt.Sprintf("mx_rbl_check:%s:%s", domain, zone))
				if !msg.Resolver.Enabled() {
					return starlark.Bool(false), nil
				}
				for _, host := range msg.Resolver.LookupMX(domain) {
					for _, ip := range msg.Resolver.LookupHost(host) {
						if zone != "" {
							if msg.Resolver.CheckRBL(ip, zone).Listed {
								return starlark.Bool(true), nil
							}
							continue
						}
						if listed, _ := msg.Resolver.CheckRBLs(ip); listed {
							return starlark.Bool(true), nil
						}
					}
				}
				return starlark.Bool(false), nil
			}),

		// ptr_matches_helo checks forward-confirmed reverse DNS, the cheapest
		// signal that a connecting host is a real mail server.
		"fcrdns_valid": unaryBool("fcrdns_valid", "ip", func(ip string) bool {
			if !msg.Resolver.Enabled() || ip == "" {
				return false
			}
			for _, name := range msg.Resolver.LookupPTR(ip) {
				for _, addr := range msg.Resolver.LookupHost(name) {
					if addr == ip {
						return true
					}
				}
			}
			return false
		}),
	}
}

// mxHasFamily reports whether a domain's MX hosts resolve to addresses of the
// requested family.
func (m *MessageContext) mxHasFamily(domain string, wantIPv6 bool) bool {
	if !m.Resolver.Enabled() {
		// Without DNS, the static MX list is all we have and it carries no
		// address-family information; report IPv4 presence only.
		return !wantIPv6 && len(m.MXRecords) > 0
	}
	for _, host := range m.Resolver.LookupMX(domain) {
		for _, addr := range m.Resolver.LookupHost(host) {
			isIPv6 := strings.Contains(addr, ":")
			if isIPv6 == wantIPv6 {
				return true
			}
		}
	}
	return false
}

func binaryDomainResolution(msg *MessageContext) *starlark.Builtin {
	return starlark.NewBuiltin("domain_resolution",
		func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var sender string
			verify := false
			if err := starlark.UnpackArgs("domain_resolution", args, kwargs, "sender", &sender, "verify?", &verify); err != nil {
				return nil, err
			}
			msg.Actions = append(msg.Actions, fmt.Sprintf("domain_resolve:%s:%t", sender, verify))

			domain := sender
			if strings.Contains(sender, "@") {
				domain = DomainOf(sender)
			}
			if !msg.Resolver.Enabled() {
				return starlark.Bool(msg.DNSResolved), nil
			}
			if verify {
				return starlark.Bool(msg.Resolver.HasMX(domain)), nil
			}
			return starlark.Bool(len(msg.Resolver.LookupHost(domain)) > 0 || msg.Resolver.HasMX(domain)), nil
		})
}

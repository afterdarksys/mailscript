# MailScript Filter Specification

Version 2.0. Applies to MailScript 2.x.

This is the normative reference for the MailScript filtering language: the
execution model, the message model, and every builtin the engine exposes.

The builtin list is generated from the live registration in
`pkg/rules/engine.go`. Run `mailscript builtins` to print the set your binary
actually supports, and `mailscript builtins --filter=dkim` to narrow it.

---

## 1. Execution model

### 1.1 Language

Rules are written in [Starlark](https://github.com/bazelbuild/starlark), a
Python-like configuration language. Available: functions, conditionals, loops,
lists, dicts, comprehensions, string methods, integer and float arithmetic.

Deliberately absent: filesystem access, network access other than through the
DNS builtins, imports, and `while` loops. A rule cannot reach outside the
message it was given.

### 1.2 Entry point

A script may define `evaluate()`:

```python
def evaluate():
    accept()
```

or perform its work at module level. If `evaluate` is defined it is called
after the module body runs. If neither the module body nor `evaluate()`
records an action, the engine appends `accept`.

### 1.3 Resource limits

Two limits bound every execution. Both are per message.

| Limit | Default | Flag | Effect on breach |
|---|---|---|---|
| Starlark steps | 10,000,000 | `--max-steps` | execution error |
| Wall clock | 5s | `--script-timeout` | execution error |

The step limit stops runaway computation. The wall-clock limit additionally
covers DNS lookups, which consume no interpreter steps. A rule that breaches
either produces an error rather than a verdict; the caller decides what to do
with a message whose policy could not be evaluated.

Regular expressions use RE2 and are compiled once and cached. RE2 has no
backtracking, so a pattern cannot be made to run in exponential time. It also
has **no backreferences** — `(\w)\1` is a compile error, not a match.

### 1.4 Failure behaviour

A malformed pattern, an unknown builtin, or a type error aborts the script
with an error naming the failing line. Nothing is silently skipped: a rule
that cannot be evaluated must not be mistaken for a rule that permitted the
message.

---

## 2. Message model

### 2.1 Header access

Headers are stored as an ordered list preserving **duplicates and original
casing**, not a map. This matters: a second `From` field is a spoofing
technique, and a map would hide it.

- Lookups are case-insensitive. `get_header("from")` and `get_header("From")`
  are equivalent.
- `get_header(name)` returns the **first** occurrence.
- `get_headers(name)` returns **all** occurrences in received order.
- `header_count(name)` reports how many times a field appears.

Folded headers are unfolded on parse: a continuation line is joined to the
previous field with a single space. The original bytes are retained for DKIM
canonicalisation, which depends on them.

### 2.2 Body access

| Builtin | Content |
|---|---|
| `get_body()` | raw body exactly as received, undecoded |
| `get_text_body()` | decoded `text/plain` part |
| `get_html_body()` | decoded `text/html` part |
| `html_to_text()` | HTML part with markup stripped |
| `search_text()` | the plain part, else HTML rendered to text, else the raw body |

Content-transfer encodings `base64` and `quoted-printable` are decoded.
Multipart trees are walked to a depth of 12. Truncated base64 decodes to its
longest valid prefix rather than failing, because a broken encoder should not
make a message unfilterable.

Content rules should prefer `search_text()`; it is the only accessor that
behaves sensibly for plain-only, HTML-only, and multipart messages alike.

### 2.3 Actions

Actions accumulate in order. Calling an action does not stop the script;
`return` does.

```python
def evaluate():
    if is_bulk():
        fileinto("Bulk")
        return          # without this, execution continues
    accept()
```

---

## 3. Authentication: reported versus verified

This distinction is the most important thing in this document.

### 3.1 Reported results are attacker-controlled

`Authentication-Results` is a plain header. Any sender can write:

```
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
```

A filter that reads that header and believes it is bypassed by anyone who can
send mail. Spammers do exactly this.

Two mechanisms make the reported values usable:

1. **Trust the authority, not the header.** Configure the authserv-id values
   your own infrastructure writes with `--trusted-authserv`. Then
   `auth_results_trusted()` reports whether the results came from you, and
   `forged_auth_results()` reports the specific attack: an untrusted header
   claiming a pass.

2. **Verify locally.** The `verify_*` builtins recompute every verdict from
   the message bytes and DNS. Nothing a sender controls affects the outcome.

| Reported (untrusted by default) | Verified (computed here) |
|---|---|
| `spf_result()` | `verify_spf()` |
| `dkim_result()` | `verify_dkim()` |
| `dmarc_result()` | `verify_dmarc()` |
| `dmarc_pass()` | `is_verified()` |

Verification requires DNS: pass `--verify` on the command line, which implies
`--dns`.

### 3.2 SPF

Implements RFC 7208. Mechanisms: `all`, `ip4`, `ip6`, `a`, `mx`, `include`,
`exists`, `ptr`. Modifiers: `redirect`, `exp`.

The processing limits are enforced, and they are security controls rather than
tuning knobs: without them a hostile SPF record turns one inbound message into
unbounded DNS traffic aimed at a third party.

| Limit | Value | Breach result |
|---|---|---|
| DNS-querying terms | 10 | `permerror` |
| Void lookups | 2 | `permerror` |
| Redirect depth | 10 | `permerror` |
| MX hosts per `mx` term | 10 | `permerror` |

SPF authenticates the **SMTP envelope**, not the `From` header. It needs the
connecting client address (`--client-ip`) and the envelope sender. With a null
reverse path the HELO identity is checked instead, per RFC 7208 section 2.4.
With neither, the result is `none` — never a guess.

A domain publishing two SPF records is a `permerror`, because which one
applies is undefined and an attacker could exploit implementations
disagreeing.

### 3.3 DKIM

Implements RFC 6376 with the RFC 8301 algorithm restrictions.

Supported: `rsa-sha256`, `ed25519-sha256`; `simple` and `relaxed`
canonicalisation for both headers and body.

Rejected, and why:

| Condition | Result | Reason |
|---|---|---|
| `rsa-sha1` | `policy` | SHA-1 collisions are practical (RFC 8301) |
| RSA key < 1024 bits | `policy` | below the RFC 8301 floor |
| `From` not in `h=` | `permerror` | the signature says nothing about the claimed sender |
| Empty `p=` in the key record | `permerror` | the key was revoked |
| Two `From` fields present | `permerror` | see below |
| No resolver configured | `temperror` | fails closed; never `pass` |

**Duplicate `From`.** Canonicalisation consumes header instances bottom-up, so
an attacker who *prepends* a second `From` leaves the signed one in place and
the signature still verifies — while the recipient's client displays the
first. MailScript refuses to report `pass` for any message carrying more than
one `From` field. Signers should additionally oversign (list `from` twice in
`h=`), but a verifier cannot assume they did.

**Body length tag.** A signature carrying `l=` covers only a prefix of the
body. Content past that offset is unsigned and can be replaced while the
signature still verifies. Such a signature verifies, but
`body_truncated` is set on it and `auth_warnings()` reports it. Do not treat
a truncated pass as authenticating the visible content.

Hash comparisons use `crypto/subtle.ConstantTimeCompare`.

### 3.4 DMARC

Implements RFC 7489. Policy discovery tries `_dmarc.<from-domain>`, then falls
back to `_dmarc.<organisational-domain>`, where the organisational domain
comes from the Public Suffix List.

Alignment is what DMARC adds over the underlying mechanisms: an SPF pass for
an unrelated bounce domain does not satisfy DMARC. Relaxed alignment (`r`,
the default) compares organisational domains; strict (`s`) requires an exact
match.

When the record was inherited from the organisational domain, `sp=` governs
rather than `p=`. A `pct=` below 100 softens a `reject` disposition to
`quarantine`, because the domain owner asked for sampling and treating a
staged rollout as full enforcement over-blocks.

### 3.5 DANE

Implements TLSA discovery per RFC 6698 and RFC 7672.

**DANE without DNSSEC is meaningless.** An attacker who can forge a TLSA
answer can equally strip it. TLSA records that did not arrive with the DNSSEC
Authenticated Data bit are reported as `insecure`, never usable. Point
`--dns-server` at a validating resolver to obtain a usable result.

Only `DANE-TA` (2) and `DANE-EE` (3) usages are accepted; RFC 7672 requires
receivers to ignore the PKIX usages for SMTP. Partial deployment across a
domain's MX hosts reports `insecure`, because an attacker can steer delivery
to the host without TLSA.

`verify_dane()` performs discovery and returns `available` when every MX has
usable, DNSSEC-validated TLSA records. `pass` is reserved for
`VerifyDANECertificate`, after a presented certificate actually matches.
DANE on a sender domain is transport-hygiene information, not authentication
of an inbound message.

### 3.6 ARC

ARC verification follows RFC 8617. `verify_arc()` locally verifies set
continuity, `cv`, the newest ARC-Message-Signature, and every ARC-Seal using
DNS-published keys. Earlier message signatures are reported for diagnostics;
they may legitimately fail after an intermediary modifies the message while
their sealed historical values remain intact. Upstream `arc=pass` claims are
never substituted for cryptographic verification.

### 3.7 MTA-STS and TLS-RPT

`check_mta_sts(domain="")` discovers `_mta-sts`, retains the DNSSEC AD state,
and validates the authenticated HTTPS policy (`version`, `mode`, `mx`, and
`max_age`). Fetches are bounded and reject redirects and private destinations.
`check_tlsrpt(domain="")` parses `_smtp._tls` report URIs and exposes whether
the DNS answer was DNSSEC-validated.

---

## 4. Header validation

`validate_headers()` returns findings, most severe first. Each is a dict with
`code`, `severity`, `header`, `message`, and `score`.

Severities: `info`, `low`, `medium`, `high`, `critical`.

### 4.1 Finding codes

**Structure**

| Code | Severity | Condition |
|---|---|---|
| `HDR_INJECTION` | critical | CR, LF, or NUL inside a field value |
| `HDR_NO_COLON` | high | header line with no field name |
| `HDR_NAME_INVALID` | high | field name outside RFC 5322 ftext |
| `HDR_8BIT_UNENCODED` | medium | raw 8-bit octets without RFC 2047 encoding |
| `HDR_INVALID_UTF8` | medium | field is not valid UTF-8 |
| `HDR_2047_MALFORMED` | low | undecodable encoded-word |
| `HDR_LINE_TOO_LONG` | low | line exceeds 998 octets |
| `HDR_COUNT_EXCESSIVE` | low | more than 200 fields |
| `HDR_SIZE_EXCESSIVE` | low | header block over 64 KiB |

**Required fields**

| Code | Severity | Condition |
|---|---|---|
| `HDR_FROM_MISSING` | high | no `From` |
| `HDR_FROM_NO_DOMAIN` | high | `From` address has no domain |
| `HDR_DATE_MISSING` | medium | no `Date` |
| `HDR_DATE_UNPARSEABLE` | medium | `Date` is not RFC 5322 |
| `HDR_DATE_FUTURE` | medium | `Date` more than 24h ahead |
| `HDR_DATE_STALE` | low | `Date` more than a year old |
| `HDR_MSGID_MISSING` | low | no `Message-ID` |
| `HDR_MSGID_MALFORMED` | low | `Message-ID` is not `<local@domain>` |
| `HDR_MSGID_DOMAIN_MISMATCH` | info | `Message-ID` domain differs from `From` |
| `HDR_SUBJECT_CONTROL` | medium | control characters in `Subject` |
| `HDR_SUBJECT_TOO_LONG` | low | `Subject` over 500 characters |

**Duplicates.** `HDR_DUP_<NAME>` for any field RFC 5322 section 3.6 permits
once. High severity for `From`, `Sender`, and `Reply-To`; medium otherwise.

**Spoofing**

| Code | Severity | Condition |
|---|---|---|
| `SPOOF_DISPLAY_NAME_ADDR` | high / medium | display name contains a different address than the real one |
| `SPOOF_DOMAIN_MIXED_SCRIPT` | high | `From` domain mixes Unicode scripts |
| `SPOOF_DISPLAY_NAME_MIXED_SCRIPT` | medium | display name mixes scripts |
| `SPOOF_MULTIPLE_FROM_ADDRS` | medium | several addresses in `From` without `Sender` |
| `SPOOF_REPLYTO_MISMATCH` | medium | `Reply-To` organisational domain differs from `From` |
| `SPOOF_ENVELOPE_MISMATCH` | low | envelope sender differs from `From` (suppressed for list mail) |
| `SPOOF_SENDER_MISMATCH` | low | `Sender` domain differs from `From` |

Japanese (Han + Hiragana + Katakana) and Korean (Han + Hangul) are not treated
as mixed scripts.

**MIME**

| Code | Severity | Condition |
|---|---|---|
| `MIME_BOUNDARY_MISSING` | medium | multipart with no boundary parameter |
| `MIME_BOUNDARY_UNUSED` | medium | declared boundary absent from the body |
| `MIME_CONTENT_TYPE_MALFORMED` | medium | unparseable `Content-Type` |
| `MIME_VERSION_MISSING` | low | `Content-Type` without `MIME-Version` |
| `MIME_CTE_UNKNOWN` | low | unrecognised transfer encoding |

**Received chain**

| Code | Severity | Condition |
|---|---|---|
| `RCVD_NONE` | medium | no `Received` fields |
| `RCVD_TIME_REVERSED` | medium | a hop predates the one below it by over a minute |
| `RCVD_EXCESSIVE` | low | more than 30 hops |
| `RCVD_PRIVATE_ORIGIN` | low | oldest hop originates from a private address |
| `RCVD_UNPARSEABLE` | low | no hop yielded from/by clauses |

**Authentication (as reported)**

`AUTH_SPF_FAIL` (high), `AUTH_DMARC_FAIL` (high, medium under `p=none`),
`AUTH_DKIM_FAIL` (medium), `AUTH_NO_ALIGNMENT` (medium),
`AUTH_SPF_SOFTFAIL` (low), `AUTH_SPF_ERROR` (low),
`AUTH_NOT_EVALUATED` (info), `AUTH_DKIM_UNVERIFIED` (info).

### 4.2 Scoring

Each finding carries a suggested score. `validation_score()` sums them;
`apply_validation_score()` folds them into the running message score with each
finding recorded as a reason.

Scores are advisory. Thresholds belong to the deployment, not the library.

---

## 5. Human mail identification

`sender_class()` returns one of:

| Class | Meaning |
|---|---|
| `human` | composed by a person for the recipient |
| `transactional` | machine-written but individually addressed: a receipt, a password reset |
| `bulk` | marketing or newsletter sent to a list |
| `list` | relayed by a discussion mailing list |
| `automated` | bounce, auto-reply, or system notification |
| `unknown` | insufficient signal |

`human_score()` returns 0 to 100. Evidence starts at 50 and moves with each
signal; `human_signals()` and `human_reasons()` expose what fired and by how
much.

**Signals against human authorship:** `Auto-Submitted` other than `no` (-30);
bulk headers such as `List-Unsubscribe`, `Feedback-ID`, `X-Campaign-Id` (-30);
`Precedence: bulk` (-25); an unattended sender local part such as `no-reply`
(-25); a campaign platform in `X-Mailer` (-20); tracking pixels (-20);
auto-generation headers (-20); VERP or SRS envelope encoding (-15); bulk
boilerplate such as "view in browser" (-15); HTML with no plain alternative
(-12); eight or more links (-12).

**Signals for human authorship:** `In-Reply-To` or `References` (+30); an
interactive mail client in `X-Mailer` (+25); a `Re:` or `Fwd:` subject (+15);
quoted text from an earlier message (+15); one to three named recipients
(+10); no links (+10); a plain-text part (+8); a personal greeting (+8);
`Message-ID` aligned with `From` (+5).

Two distinctions the classifier is careful about:

- **`List-Unsubscribe` does not mean discussion list.** Bulk sender
  requirements have made it near-universal on marketing mail. Only `List-Id`
  and `List-Post` classify a message as `list`.
- **A generic salutation is not a greeting.** "Dear Valued Customer" scores as
  bulk, "Hi Rachel," as personal.

---

## 6. Machine learning

Binary classification defaults to Robinson-Fisher chi-square combining over
raw token counts, producing useful scores near 0 and 1 plus an explicit
unsure band. Robinson geometric mean and legacy multinomial Naive Bayes are
selectable. TF-IDF remains available for similarity, explanation, and
multi-class Bayes. Everything is implemented natively with no external
runtime dependencies.

### 6.1 Training

```bash
mailscript train --spam=spam.mbox --ham=ham.mbox --out=spam.json.gz
mailscript train --label=phish:phish.mbox --label=bulk:bulk.mbox \
  --label=legit:inbox.mbox --scorer=bayes --out=triage.json.gz
mailscript train --spam=spam.mbox --ham=ham.mbox --scorer=robinson \
  --feature-selection=chi2 --osb-window=5 --out=ordered.json.gz
```

A held-out split (20% by default) is scored automatically, so the reported
accuracy reflects unseen mail. Per-class precision and recall are printed
because a single accuracy figure hides the failure that matters: a model that
misclassifies legitimate mail is worse than no model.

The analyzer is mail-aware. URLs collapse to `url:<host>` so randomised paths
do not fragment the feature space; addresses collapse to `emaildom:<domain>`;
shouting and repeated punctuation become their own features.
Chi-square feature selection ranks terms by dependence on class. Optional OSB
features preserve token order through bounded sparse bigrams.

### 6.2 Use

```bash
mailscript test --script=filter.star --model=spam.json.gz --eml=message.eml
```

```python
def evaluate():
    if ml_unsure():
        fileinto("Review")
    elif ml_score("spam") > 0.95:
        quarantine()
        return
    accept()
```

`ml_explain()` returns the terms that drove the classification, which is what
makes a quarantine decision defensible to the recipient.

### 6.3 BERT tokenization

`bert_tokens()` and `bert_token_ids()` perform WordPiece tokenization against
a `vocab.txt` supplied with `--bert-vocab`. This produces the token IDs a
transformer consumes and is useful as a feature extractor on its own, because
WordPiece segments unknown words into meaningful subwords.

No transformer inference ships with MailScript: it would require cgo and a
model artefact, and would add tens of milliseconds per message. Implement the
`ml.Embedder` interface to plug in a backend, then use `embed()` and
`embed_similarity()`.

### 6.4 GoLearn

Additional algorithms (kNN, decision trees, random forests) are available
behind a build tag:

```bash
go build -tags golearn -o mailscript ./cmd/mailscript
```

They are optional because GoLearn's learners need dense matrices, which do not
suit a full email vocabulary, and because parts of the library require cgo.
The native classifier is faster and adequate for spam. `golearn_available()` reports whether they are compiled in.

---

## 7. DNS

DNS is **off by default**. Rules stay deterministic and offline unless
`--dns` is passed. Without it, the DNS builtins return the static values on
the message context rather than blocking, so a rule written for a gateway
still runs in the test harness.

Answers are cached with a 5-minute TTL and a 3-second per-query timeout. A
mail gateway will otherwise re-query the same sender domain once per message.

`--dns-server` directs queries at a specific resolver. For DANE it must be a
DNSSEC-validating one.

---

## 8. Builtin reference

253 builtins in the current release. `mailscript builtins` prints the exact
set for your binary.

### 8.1 Actions

`accept` `discard` `drop` `bounce` `quarantine` `reject` `defer`
`fileinto(folder)` `divert_to(email_address)` `screen_to(email_address)`
`redirect(email_address)` `tag(label)` `auto_reply(text)`
`add_to_next_digest()` `log_entry(message)`
`reply_with_smtp_error(code, text=None)` `reply_with_smtp_dsn(dsn)`
`set_dlp(mode, target)` `skip_dlp(mode, target)` `skip_malware_check(sender)`
`skip_spam_check(sender)` `skip_whitelist_check(ip)`
`force_second_pass(mailserver)` `get_actions()` `has_action(name)`
`clear_actions()`

### 8.2 Headers

`get_header(name)` `get_headers(name)` `has_header(name)`
`header_count(name)` `header_names()` `all_headers()`
`add_header(name, value)` `remove_header(name)` `header_size()`
`num_envelope()`

`add_header` rejects CR, LF, and NUL in either argument: the engine will not
construct the injection its own validator flags.

### 8.3 Matching

`regex_match(pattern, text)` `regex_find(pattern, text)`
`regex_find_all(pattern, text, limit=-1)` `count_matches(pattern, text)`
`header_matches(name, pattern)` `body_matches(pattern)` `search_body(text)`
`search_body_ci(text)` `search_headers(text)` `any_match(patterns, text)`

### 8.4 Validation

`validate_headers(min_severity="")` `validation_codes()` `has_finding(code)`
`finding_count(min_severity="")` `max_severity()` `validation_score()`
`apply_validation_score(min_severity="")` `is_valid_address(value)`
`is_valid_message_id(value)`

### 8.5 Identity and domains

`parse_address(value)` `parse_address_list(value)` `from_address()`
`from_domain()` `from_local()` `from_display_name()` `reply_to_domain()`
`sender_domain()` `get_sender_domain()` `envelope_from()`
`envelope_from_domain()` `envelope_to()` `to_addresses()` `cc_addresses()`
`recipient_count()` `registered_domain(host)` `public_suffix(host)`
`same_org_domain(a, b)` `is_subdomain_of(host, parent)`
`to_unicode_domain(host)` `to_ascii_domain(host)` `skeleton(value)`
`looks_like(candidate, target)` `looks_like_any(candidate, targets)`
`is_mixed_script(value)` `unicode_scripts(value)` `display_name_spoofed()`

### 8.6 Authentication, verified

`verify_auth(dane=False)` `verify_spf()` `verify_dkim()` `verify_dmarc()`
`verify_arc()` `verify_arc_details()`
`verify_dane(domain="")` `is_verified()` `auth_disposition()`
`auth_warnings()` `auth_summary()` `authentication_results(authserv_id="")`
`verify_spf_details()` `verify_dkim_details()` `verify_dmarc_details()`
`check_mta_sts(domain="")` `check_tlsrpt(domain="")`

### 8.7 Authentication, as reported

`auth_results()` `spf_result()` `dkim_result()` `dmarc_result()`
`arc_result()` `spf_domain()` `dkim_domains()` `has_auth_results()`
`has_dkim_signature()` `dmarc_pass()` `dmarc_policy()`
`spf_aligned(strict=False)` `dkim_aligned(strict=False)` `is_authenticated()`
`auth_results_trusted()` `untrusted_authservs()` `forged_auth_results()`

### 8.8 Received chain

`received_chain()` `received_count()` `received_hop(level)`
`check_received_header(level)` `get_received_headers()` `origin_ip()`
`get_sender_ip()` `is_private_ip(ip)` `hop_ips()`

### 8.9 Content and URLs

`get_body()` `get_text_body()` `get_html_body()` `search_text()`
`html_to_text()` `has_html()` `has_plain()` `html_text_ratio()`
`mime_parts()` `part_count()` `has_content_type(media_type)` `get_urls()`
`get_url_domains()` `url_count()` `has_url_shortener()`
`url_display_mismatches()` `has_url_display_mismatch()`
`url_domains_off_brand()` `tracking_pixel_count()` `has_tracking_pixel()`
`entropy(text)` `uppercase_ratio(text)` `non_ascii_ratio(text)`
`body_entropy()` `subject_shouting()`

### 8.10 Attachments

`get_attachments()` `attachment_count()` `has_attachment()`
`attachment_names()` `total_attachment_size()` `has_attachment_ext(extensions)`
`has_executable_attachment()` `has_macro_attachment()`
`has_archive_attachment()` `double_extension_attachments()`
`rtl_override_attachments()` `attachment_hashes()`

### 8.11 Human identification

`human_score()` `sender_class()` `is_human()` `is_automated()` `is_bulk()`
`is_transactional()` `is_list_mail()` `human_reasons()` `human_signals()`
`has_human_signal(name)` `is_threaded()` `is_auto_submitted()`
`is_noreply_sender()` `has_unsubscribe()`
`ai_generated_score()` `ai_generated_class()` `is_ai_generated(threshold=70)`
`ai_generation_reasons()`

AI identification uses declared provenance and sending-system markers. It
does not label mail from prose style alone, which is not a dependable signal.

### 8.12 Machine learning

`ml_available()` `ml_models()` `ml_scorer(model="")`
`ml_unsure(model="", text="")` `classify(model="", text="")`
`classify_label(model="")` `ml_score(class, model="", text="")`
`ml_explain(model="", limit=10)` `tfidf_score(class, model="")`
`tokenize(text="", ngram_max=1)` `token_vector(model="", text="", limit=50)`
`text_similarity(a, b, model="")` `message_similarity(reference, model="")`
`classifier_text()` `spam_probability(model="")` `bert_available()`
`bert_vocab_size()` `bert_tokens(text="")`
`bert_token_ids(text="", max_len=0, add_special=True)` `embedders()`
`embed(backend, text="")` `embed_similarity(backend, a, b)`
`golearn_available()`

### 8.13 DNS

`dns_available()` `dns_check(domain)` `dns_resolution(domain)` `dns_a(domain)`
`dns_txt(domain)` `dnssec_txt(name)` `dns_ptr(ip)` `get_mx_records(domain)` `valid_mx(domain)`
`is_mx_ipv4(domain)` `is_mx_ipv6(domain)` `domain_resolution(sender, verify=False)`
`rbl_check(ip, rbl_server="")` `rbl_lookup(ip, rbl_server="")`
`get_rbl_status()` `mx_in_rbl(domain, rbl_server="")` `fcrdns_valid(ip)`

### 8.14 Scoring and lists

`add_score(points, reason="")` `get_score()` `get_score_reasons()`
`set_score(value, reason="")` `reset_score()` `in_list(list_name, value)`
`domain_in_list(list_name, value)` `list_names()` `list_size(list_name)`

Lists are loaded with `--list name=path`, one entry per line, `#` for
comments. `domain_in_list` honours subdomains, so one entry covers a zone.

### 8.15 Metadata

`getmimetype()` `getspamscore()` `getvirusstatus()` `body_size()`
`message_size()` `get_instance()` `get_instance_name()` `now()`
`date_skew_seconds()` `message_age_seconds()` `parse_date(value)`
`protect_metadata(policy="standard", extra=[])`

Metadata policies are `minimal`, `standard`, and `strict`. Removals happen
after rule evaluation so authentication always sees the original wire bytes.

### 8.16 Legacy

Retained for compatibility with MailScript 1.x scripts:
`get_recipient_did()` `get_content_filter()` `get_content_filter_name()`
`get_content_filter_rules()` `set_content_filter_rules(rule)`

---

## 9. Compatibility

MailScript 1.x scripts run unchanged. Every 1.x builtin is still registered
with its original signature.

Two behaviour changes could affect an existing script:

1. **`get_header` is now case-insensitive.** Previously `get_header("from")`
   returned `""` when the message had `From`. A script that relied on that
   returning empty will now see a value.
2. **`regex_match` raises on an invalid pattern** rather than silently
   returning false. A script with a broken pattern now fails loudly. This is
   intentional: a filter that silently matches nothing is a filter that has
   stopped working.

---

## 10. Worked example

```python
# Phishing policy combining every layer.
BRANDS = ["paypal.com", "microsoft.com", "google.com", "apple.com"]

def evaluate():
    # 1. Structural integrity. Header injection is never legitimate.
    if has_finding("HDR_INJECTION"):
        log_entry("header injection attempt")
        drop()
        return

    # 2. Authentication, verified locally. A forged Authentication-Results
    #    header has no effect on this.
    #
    #    Only penalise a failure when verification could actually run. With
    #    DNS unavailable every message would otherwise look unauthenticated,
    #    which turns an outage into a false-positive storm.
    if dns_available():
        if not is_verified():
            add_score(4.0, "sender did not prove control of " + from_domain())
            if auth_disposition() == "reject":
                log_entry("DMARC reject: " + auth_summary())
                quarantine()
                return

    # 3. A message claiming a pass from an authority that is not ours is a
    #    deliberate forgery, not a misconfiguration.
    if forged_auth_results():
        log_entry("forged Authentication-Results from " + str(untrusted_authservs()))
        add_score(6.0, "forged authentication header")

    # 4. Brand impersonation via a lookalike domain.
    impersonated = looks_like_any(from_domain(), BRANDS)
    if impersonated:
        log_entry("domain resembles " + impersonated)
        add_score(7.0, "lookalike domain")

    # 5. Display name claiming an address it does not own.
    if display_name_spoofed():
        add_score(5.0, "display name spoofing")

    # 6. Links whose visible text disagrees with their destination.
    if has_url_display_mismatch():
        add_score(5.0, "link text disagrees with href")

    # 7. Dangerous attachments.
    if has_executable_attachment() or len(double_extension_attachments()) > 0:
        log_entry("executable attachment")
        quarantine()
        return

    # 8. Statistical classification, if a model is loaded.
    if ml_available() and ml_score("spam") > 0.95:
        add_score(4.0, "classifier: spam")

    # 9. Fold in structural findings, then decide once.
    apply_validation_score(min_severity="medium")

    if get_score() >= 10.0:
        log_entry("blocked, score " + str(int(get_score())))
        quarantine()
        return

    if get_score() >= 5.0:
        add_header("X-MailScript-Suspicious", "score=" + str(int(get_score())))

    # 10. Route by sender class.
    if is_bulk():
        fileinto("Bulk")
        return

    accept()
```

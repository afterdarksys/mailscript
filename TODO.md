# TODO

Outstanding work, roughly in priority order. Each item records why it
matters, not just what to do.

---

## 1. Known defects

### 1.1 `forwardViaGRPC` reports success without forwarding

`cmd/mailscript/grpc_server.go:170`

```go
// TODO: Actually send via SMTP protocol
log.Printf("Would forward message to %s", s.proxy.upstreamServer)
return nil
```

A gRPC caller passing `forward_to_upstream=true` gets `accepted=true` back
while the message is silently dropped. This is a fail-open path: the caller
believes the mail was relayed and has no way to learn otherwise.

Fix: implement the SMTP conversation, or return an error until it exists. The
SMTP session path already has a working `forwardToUpstream` in `proxy.go` that
can be reused.

### 1.2 Documented ML thresholds can never fire

`SPEC.md:413`, `SPEC.md:679`, `examples/phishing-defense.star:116`

The examples gate on `ml_score("spam") > 0.95`, but the current classifier
maxes out around 0.70 on blatant spam:

| Input | P(spam) |
|---|---|
| Blatant spam, every corpus keyword | 0.696 |
| Obvious ham | 0.208 |
| Genuinely ambiguous | 0.468 |

So every shipped ML rule is inert. Root cause is a modelling mismatch:
multinomial Naive Bayes expects term *counts*, but it is being fed
L2-normalised TF-IDF weights (~0.1-0.3 each). That damps the log-odds sum and
softmax pulls the posterior toward 0.5.

Two ways out, and they are not equivalent:

- Correct the thresholds to match reality. Cheap, honest, leaves the
  compressed range in place.
- Fix the scoring properly (section 2). Preferred.

### 1.3 gRPC service is a stub

`cmd/mailscript/grpc_server.go:184`

`startGRPCServer` constructs a server, never registers the service, and blocks
on `select {}`. The proto is not generated. README and SPEC both advertise the
gRPC interface as working.

Either generate the bindings and register the service, or stop advertising it
until it exists.

---

## 2. Classifier: Robinson and Fisher

The statistical core is the weakest component. For context, here is what the
field actually uses:

| Filter | Statistical core |
|---|---|
| bogofilter (2002) | Robinson geometric mean **and** Robinson-Fisher chi-square |
| SpamBayes | chi-square combining; origin of the "unsure" band |
| SpamAssassin | Robinson chi-square Bayes, plus rules and network tests |
| CRM114 | Markovian SBPH, later OSB/OSBF |
| DSPAM | chi-square, Robinson, Bayes, Markovian, selectable |
| rspamd (current SOTA) | OSB-Bayes, neural module, fuzzy hashing |
| **MailScript** | plain multinomial Naive Bayes on TF-IDF |

bogofilter shipped both of the algorithms below in 2002. We are behind.

### 2.1 Token count store

Robinson and Fisher operate on raw per-token `(spam_count, ham_count)`, not on
TF-IDF vectors. They will not bolt onto the existing `Vectorizer`; they need a
separate store. Both methods are inherently **binary**, so a model requesting
them with more than two classes should be rejected rather than silently
falling back.

### 2.2 Robinson's geometric mean

```
p(w) = (b(w)/nbad) / ((b(w)/nbad) + (g(w)/ngood))
f(w) = (s*x + n*p(w)) / (s + n)          n = b(w) + g(w)

P = 1 - (prod(1 - f(w)))^(1/n)
Q = 1 - (prod f(w))^(1/n)
S = (P - Q) / (P + Q)                    normalise to [0,1]
```

The `s`/`x` prior is the point: it handles tokens seen once or twice
correctly, where the current Laplace smoothing treats a token seen once much
like one seen fifty times. Accumulate in log space to avoid underflow.

### 2.3 Fisher (Robinson-Fisher) chi-square combining

```
H = ChiSquareP(-2 * sum(ln f(w)),       2n)     spamminess
S = ChiSquareP(-2 * sum(ln(1 - f(w))),  2n)     haminess
I = (1 + H - S) / 2
```

This is SpamBayes' method. It produces a strongly *bimodal* score with a
genuine unsure band in the middle, which is what a quarantine decision
actually wants — unlike the current mush between 0.21 and 0.70.

Score only the most interesting tokens (greatest distance from 0.5), typically
15-150. Using every token dilutes the signal.

`pkg/ml/chisq.go` already implements `ChiSquareP` for even degrees of freedom
and is committed as groundwork. **It is currently unreferenced**; it exists
for this work and nothing else.

### 2.4 Surface

```
ml_scorer()      -> "bayes" | "robinson" | "fisher"
ml_unsure()      -> true when the score lands in the unsure band
ml_score(class)  -> well separated across [0,1]
```

Target: blatant spam near 0.99, ham near 0.01, ambiguous explicitly unsure.

---

## 3. Deferred algorithms

### 3.1 Markovian / OSB features

CRM114-style sparse binary polynomial hashing, or the orthogonal sparse
bigrams rspamd uses. Captures word *order*, which bag-of-words discards
entirely. Historically the accuracy leader.

Deferred on cost: roughly 5x features per token, model size from MB to tens of
MB, slower training. Scoring stays sub-millisecond.

### 3.2 Chi-square feature selection

Distinct from 2.3, despite the shared name. Tests term/class independence to
prune the vocabulary. Cheap, complements everything else, would reduce model
size.

---

## 4. DANE

### 4.1 `CheckDANE` returns `pass` for discovery alone

`pkg/authverify/dane.go`

`CheckDANE` reports `DANEPass` when a domain merely publishes
DNSSEC-validated TLSA records. `MatchedRecord` stays `-1`; no certificate was
checked. A rule author writing `verify_dane()["result"] == "pass"` would
reasonably conclude the message was DANE-authenticated. It was not.

Proposal: add `DANEAvailable = "available"` for discovery and reserve `pass`
for an actual `VerifyDANECertificate` match. Touches SPEC section 3.5 and the
`verify_dane` docs.

### 4.2 DANE on inbound is a sender-hygiene signal, not authentication

DANE secures *outbound* delivery TLS. Checking the sender domain's MX TLSA
describes mail we would send *to* them; it says nothing about the authenticity
of a message we received. Worth stating plainly in SPEC so nobody scores
inbound mail on it.

### 4.3 `VerifyDANECertificate` has no test coverage

It needs a TLS handshake or certificate fixtures. This is the real gap behind
the code-review graph flagging `CheckDANE`.

---

## 5. DKIM details

Neither of these is exploitable; both fail closed. Recorded so the decision is
deliberate rather than accidental.

### 5.1 Tag names are lowercased, but the RFC says case-sensitive

`parseDKIMTags`, RFC 6376 section 3.2.

`B=` therefore collides with `b=`: an injected `B=junk` becomes the first `b`,
the real signature is dropped as a duplicate, and verification fails. An
attacker gains nothing by forcing their own forgery to fail.

Lowercasing also buys leniency toward nonconformant publishers — a key record
written `P=` would otherwise read as revoked. Decide strict versus lenient
rather than leaving it implicit.

### 5.2 Duplicate tags silently take the first

RFC 6376 says duplicate tags MUST NOT occur. Combined with
`stripSignatureValue` removing *all* `b=` occurrences while the parser keeps
one, a duplicated `b=` changes the hashed bytes and fails closed. Rejecting
outright would be stricter.

---

## 6. Test coverage

- `VerifyDANECertificate` — see 4.3.
- SPF macro expansion (`%{s}`, `%{d}`, `%{i}`) is unimplemented; unsupported
  macros should be confirmed to produce `permerror` rather than a silent
  mismatch.
- ARC chain validation is parsed but never verified.
- The proxy has no automated test. It was exercised by hand over a live SMTP
  session (duplicate `From` correctly rejected); that should be a test.

---

## 7. Tooling

### 7.1 code-review-graph MCP server is missing `torch`

`list_graph_stats_tool` fails with `name 'torch' is not defined`, and
`semantic_search_nodes` presumably shares the code path. Build, architecture,
query and change-detection tools all work.

Pre-existing environment issue, not caused by this repo. Install torch in the
server's environment, or ignore if semantic search is unused.

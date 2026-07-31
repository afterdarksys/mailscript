package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPolicyModulesLoadFromRootDirectory(t *testing.T) {
	dir := t.TempDir()
	module := filepath.Join(dir, "auth.star")
	if err := os.WriteFile(module, []byte("def apply():\n    add_header(\"X-Module\", \"auth\")\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx := mustParse(t, wellFormed)
	opts := DefaultOptions()
	opts.Filename = filepath.Join(dir, "main.star")
	err := ExecuteEngineWithOptions("load(\"auth.star\", \"apply\")\ndef evaluate():\n    apply()\n    accept()\n", ctx, opts)
	if err != nil {
		t.Fatal(err)
	}
	if ctx.ModifiedHeaders["X-Module"] != "auth" {
		t.Fatalf("module did not execute: %v", ctx.ModifiedHeaders)
	}
}

// TestPolicyModulesLoadWithBareRelativeFilename reproduces the real
// `mailscript proxy --script=filter.star` invocation, where opts.Filename is
// a bare name with no path separator and the process's cwd is the policy
// directory. Gating thread.Load installation on "does Filename contain a
// separator" left load() unavailable for exactly this case — every message
// failed with a script error on any policy using load().
func TestPolicyModulesLoadWithBareRelativeFilename(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "auth.star"), []byte("def apply():\n    add_header(\"X-Module\", \"auth\")\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	origWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(origWD) })

	ctx := mustParse(t, wellFormed)
	opts := DefaultOptions()
	opts.Filename = "main.star" // no path separator, as --script=main.star produces
	err = ExecuteEngineWithOptions("load(\"auth.star\", \"apply\")\ndef evaluate():\n    apply()\n    accept()\n", ctx, opts)
	if err != nil {
		t.Fatalf("ExecuteEngineWithOptions() with a bare relative Filename: %v", err)
	}
	if ctx.ModifiedHeaders["X-Module"] != "auth" {
		t.Fatalf("module did not execute: %v", ctx.ModifiedHeaders)
	}
}

// Threats: examples/policy-bundle.star (the shipped reference composition)
// used to let apply_ai_policy()'s True return short-circuit evaluate()
// before the authentication-score quarantine gate ran. is_ai_generated()
// (examples/policies/ai-mail.star, backed by MessageContext.AssessAI) is
// driven entirely by sender-supplied headers like X-AI-Agent — nothing
// verifies them. A message with a spoofed X-AI-Agent header sailed through
// as "AI/Declared" even when the accumulated authentication-failure score
// would otherwise have triggered quarantine, and the privacy-stripping step
// after it was skipped too. This test isolates that exact control-flow
// shape — score check must run regardless of AI classification — against
// the real ai-mail.star module (so the header-spoofing behavior under test
// is the genuine, unmocked implementation), without depending on live DNS
// for the authentication score (add_score is called directly, standing in
// for what apply_authentication() would add on a real SPF/DKIM/ARC
// failure).
func TestAIClassificationDoesNotBypassScoreBasedQuarantine(t *testing.T) {
	aiModule := filepath.Join("..", "..", "examples", "policies", "ai-mail.star")
	if _, err := os.Stat(aiModule); err != nil {
		t.Skipf("examples/policies/ai-mail.star not found: %v", err)
	}

	root := `
load("ai-mail.star", "apply_ai_policy")

def evaluate():
    add_score(7.0, "simulated authentication failure")
    ai_classified = apply_ai_policy()
    if get_score() >= 5:
        quarantine()
        return
    if ai_classified:
        return
    accept()
`
	raw := "From: attacker@example.test\r\nTo: victim@example.test\r\nSubject: hi\r\nX-AI-Agent: yes\r\n\r\nbody\r\n"
	ctx := mustParse(t, raw)
	opts := DefaultOptions()
	opts.Filename = filepath.Join(filepath.Dir(aiModule), "root.star")
	if err := ExecuteEngineWithOptions(root, ctx, opts); err != nil {
		t.Fatalf("ExecuteEngineWithOptions() error = %v", err)
	}
	if !hasAction(ctx.Actions, "quarantine") {
		t.Fatalf("a spoofed X-AI-Agent header bypassed quarantine for a message scoring >= 5: actions=%v", ctx.Actions)
	}
}

// runScript executes a script against a parsed message and returns the context.
func runScript(t *testing.T, raw, script string) *MessageContext {
	t.Helper()
	ctx := mustParse(t, raw)
	if err := ExecuteEngine(script, ctx); err != nil {
		t.Fatalf("ExecuteEngine: %v", err)
	}
	return ctx
}

func hasAction(actions []string, want string) bool {
	for _, a := range actions {
		if a == want || strings.HasPrefix(a, want+":") {
			return true
		}
	}
	return false
}

func TestEngineRunsEvaluateAndRecordsActions(t *testing.T) {
	ctx := runScript(t, wellFormed, `
def evaluate():
    if get_header("Subject") == "Lunch":
        fileinto("Personal")
        return
    accept()
`)

	if !hasAction(ctx.Actions, "fileinto") {
		t.Fatalf("expected a fileinto action, got %v", ctx.Actions)
	}
}

func TestEngineDefaultsToAcceptWithoutEvaluate(t *testing.T) {
	ctx := runScript(t, wellFormed, `x = 1 + 1`)

	if !hasAction(ctx.Actions, "accept") {
		t.Errorf("a script with no evaluate() and no actions should accept, got %v", ctx.Actions)
	}
}

// An infinite loop must be stopped rather than wedging an SMTP worker.
func TestEngineEnforcesStepLimit(t *testing.T) {
	ctx := mustParse(t, wellFormed)
	opts := DefaultOptions()
	opts.MaxSteps = 100_000

	err := ExecuteEngineWithOptions(`
def evaluate():
    n = 0
    for i in range(100000000):
        n += i
`, ctx, opts)

	if err == nil {
		t.Fatal("expected the step limit to stop an unbounded loop")
	}
}

func TestEngineReportsScriptErrorsWithBacktrace(t *testing.T) {
	ctx := mustParse(t, wellFormed)

	err := ExecuteEngine(`
def evaluate():
    fail_here()
`, ctx)

	if err == nil {
		t.Fatal("expected an error from an undefined function")
	}
	if !strings.Contains(err.Error(), "fail_here") {
		t.Errorf("expected the error to name the failing call, got %v", err)
	}
}

// A malformed regex must fail loudly rather than silently matching nothing.
func TestEngineRejectsBadRegex(t *testing.T) {
	ctx := mustParse(t, wellFormed)

	err := ExecuteEngine(`
def evaluate():
    regex_match("[unclosed", "text")
`, ctx)

	if err == nil {
		t.Fatal("expected an error from an invalid pattern")
	}
}

// add_header must refuse to construct the injection the validator flags.
func TestAddHeaderRejectsInjection(t *testing.T) {
	ctx := mustParse(t, wellFormed)

	err := ExecuteEngine(`
def evaluate():
    add_header("X-Evil", "value\r\nBcc: victim@example.net")
`, ctx)

	if err == nil {
		t.Fatal("add_header must reject CR/LF in a value")
	}
}

func TestScoringBuiltins(t *testing.T) {
	ctx := runScript(t, wellFormed, `
def evaluate():
    add_score(2.5, "suspicious subject")
    add_score(1.5, "no dkim")
    if get_score() > 3.0:
        quarantine()
`)

	if ctx.Score != 4.0 {
		t.Errorf("expected a score of 4.0, got %v", ctx.Score)
	}
	if len(ctx.ScoreReasons) != 2 {
		t.Errorf("expected two score reasons, got %v", ctx.ScoreReasons)
	}
	if !hasAction(ctx.Actions, "quarantine") {
		t.Errorf("expected quarantine, got %v", ctx.Actions)
	}
}

func TestHeaderBuiltinsAreCaseInsensitive(t *testing.T) {
	ctx := runScript(t, wellFormed, `
def evaluate():
    if get_header("subject") == "" or not has_header("FROM"):
        bounce()
        return
    accept()
`)

	if hasAction(ctx.Actions, "bounce") {
		t.Error("header lookups should be case-insensitive")
	}
}

func TestValidationBuiltinsExposeFindings(t *testing.T) {
	raw := "From: Real <a@example.com>\r\nFrom: Fake <b@evil.example>\r\nSubject: Hi\r\n\r\nBody\r\n"
	ctx := runScript(t, raw, `
def evaluate():
    if has_finding("HDR_DUP_FROM"):
        log_entry("duplicate From detected")
        quarantine()
        return
    accept()
`)

	if !hasAction(ctx.Actions, "quarantine") {
		t.Fatalf("expected quarantine, got %v", ctx.Actions)
	}
	if len(ctx.LogEntries) == 0 {
		t.Error("expected a log entry")
	}
}

func TestHumanBuiltinsAreExposed(t *testing.T) {
	raw := "From: Deals <no-reply@shop.example>\r\n" +
		"Subject: Sale\r\nList-Unsubscribe: <https://x.example/u>\r\nPrecedence: bulk\r\n\r\nBuy now\r\n"

	ctx := runScript(t, raw, `
def evaluate():
    log_entry("class=" + sender_class())
    if is_bulk():
        fileinto("Bulk")
        return
    accept()
`)

	if !hasAction(ctx.Actions, "fileinto") {
		t.Fatalf("expected the bulk message to be filed, got %v", ctx.Actions)
	}
}

func TestAIGeneratedMailCanBeFiltered(t *testing.T) {
	raw := "From: agent@example.com\r\nX-Generated-By: OpenAI agent\r\nSubject: update\r\n\r\nHello\r\n"
	ctx := runScript(t, raw, `
def evaluate():
    if is_ai_generated(threshold=80):
        fileinto("AI")
        return
    accept()
`)
	if !hasAction(ctx.Actions, "fileinto") {
		t.Fatalf("expected AI mail to be filed, got %v", ctx.Actions)
	}
}

func TestMetadataProtectionRecordsPolicyRemovals(t *testing.T) {
	ctx := runScript(t, wellFormed, `
def evaluate():
    protect_metadata("standard", extra=["X-Private-Trace"])
    accept()
`)
	for _, name := range []string{"X-Originating-IP", "X-Envelope-To", "X-Private-Trace"} {
		found := false
		for _, removed := range ctx.RemovedHeaders {
			if strings.EqualFold(name, removed) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s was not scheduled for removal: %v", name, ctx.RemovedHeaders)
		}
	}
}

func TestContentBuiltinsExtractURLs(t *testing.T) {
	raw := "From: a@example.com\r\nSubject: Hi\r\nContent-Type: text/html\r\n\r\n" +
		"<html><a href=\"https://evil.example/login\">https://bank.example</a></html>\r\n"

	ctx := runScript(t, raw, `
def evaluate():
    if has_url_display_mismatch():
        log_entry("link text disagrees with destination")
        quarantine()
        return
    accept()
`)

	if !hasAction(ctx.Actions, "quarantine") {
		t.Fatalf("expected the display mismatch to be caught, got %v; logs %v", ctx.Actions, ctx.LogEntries)
	}
}

func TestAttachmentBuiltins(t *testing.T) {
	raw := "From: a@example.com\r\nSubject: Invoice\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: multipart/mixed; boundary=\"XX\"\r\n\r\n" +
		"--XX\r\nContent-Type: text/plain\r\n\r\nSee attached.\r\n" +
		"--XX\r\nContent-Type: application/octet-stream\r\n" +
		"Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\r\n\r\n" +
		"MZ\r\n--XX--\r\n"

	ctx := runScript(t, raw, `
def evaluate():
    if has_executable_attachment() or len(double_extension_attachments()) > 0:
        drop()
        return
    accept()
`)

	if !hasAction(ctx.Actions, "drop") {
		t.Fatalf("expected the executable attachment to be dropped, got %v", ctx.Actions)
	}
}

func TestListBuiltins(t *testing.T) {
	ctx := mustParse(t, wellFormed)
	ctx.Lists = map[string]map[string]bool{
		"blocked": {"evil.example": true},
		"allowed": {"example.com": true},
	}

	if err := ExecuteEngine(`
def evaluate():
    if domain_in_list("allowed", from_domain()):
        add_header("X-Allowed", "yes")
        accept()
        return
    quarantine()
`, ctx); err != nil {
		t.Fatalf("ExecuteEngine: %v", err)
	}

	if ctx.ModifiedHeaders["X-Allowed"] != "yes" {
		t.Errorf("expected the allow list to match, actions %v", ctx.Actions)
	}
}

// Without a resolver, DNS builtins must degrade rather than block or panic.
func TestNetworkBuiltinsDegradeWithoutResolver(t *testing.T) {
	ctx := runScript(t, wellFormed, `
def evaluate():
    if dns_available():
        log_entry("dns on")
    else:
        log_entry("dns off")
    dns_check("example.com")
    accept()
`)

	if len(ctx.LogEntries) == 0 || ctx.LogEntries[0] != "dns off" {
		t.Errorf("expected dns to report unavailable, got %v", ctx.LogEntries)
	}
}

func TestTimeoutCancelsLongScript(t *testing.T) {
	ctx := mustParse(t, wellFormed)
	opts := DefaultOptions()
	opts.Timeout = 50 * time.Millisecond
	opts.MaxSteps = 1 << 62 // ensure the timeout, not the step limit, fires

	err := ExecuteEngineWithOptions(`
def evaluate():
    n = 0
    for i in range(1000000000):
        n += i
`, ctx, opts)

	if err == nil {
		t.Fatal("expected the timeout to cancel the script")
	}
}

func TestLegacyScriptsStillRun(t *testing.T) {
	// The original example filter, unchanged.
	ctx := runScript(t, wellFormed, `
def evaluate():
    score = getspamscore()
    subject = get_header("Subject")
    from_addr = get_header("From")
    log_entry("Checking message from: " + from_addr)
    if score > 7.0:
        quarantine()
        return
    if regex_match("(?i)(viagra|casino)", subject):
        fileinto("Spam")
        return
    accept()
`)

	if !hasAction(ctx.Actions, "accept") {
		t.Errorf("expected the legacy script to accept, got %v", ctx.Actions)
	}
}

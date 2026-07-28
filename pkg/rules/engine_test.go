package rules

import (
	"strings"
	"testing"
	"time"
)

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

package rules

import "testing"

func TestAnalyzerAggregationAndBuiltins(t *testing.T) {
	ctx := NewMessageContext()
	ctx.AnalyzerResults = []AnalyzerResult{
		{Analyzer: "ocr", Verdict: "clean", Score: 0.05},
		{
			Analyzer: "capa", Verdict: "suspicious", Score: 0.82, Deferred: true,
			Categories: []string{"execution"},
			Findings: []AnalyzerFinding{{
				Source: "capa", Code: "process/create-powershell",
				Summary: "Executable can launch PowerShell", Confidence: 0.91,
			}},
		},
	}

	if got := ctx.ThreatVerdict(); got != "suspicious" {
		t.Fatalf("ThreatVerdict() = %q", got)
	}
	if got := ctx.ThreatScore(); got != 0.82 {
		t.Fatalf("ThreatScore() = %v", got)
	}
	if !ctx.AnalysisPending() {
		t.Fatal("AnalysisPending() = false")
	}

	script := `
def main():
    if threat_verdict() != "suspicious": fail("bad verdict")
    if threat_score() < 0.8: fail("bad score")
    if not analysis_pending(): fail("not pending")
    if not has_finding("process/create-powershell"): fail("missing finding")
    if not has_analysis_finding("process/create-powershell"): fail("missing analysis finding")
    if not has_capability("process/create-powershell"): fail("missing capability")
    if threat_categories() != ["execution"]: fail("bad categories")
    if threat_reasons() != ["Executable can launch PowerShell"]: fail("bad reasons")
    findings = analysis_findings()
    if len(findings) != 1 or findings[0]["source"] != "capa": fail("bad findings")
    log_entry("analysis builtins work")
main()
`
	if err := ExecuteEngine(script, ctx); err != nil {
		t.Fatal(err)
	}
}

func TestThreatVerdictIsUnknownWithoutAnalyzers(t *testing.T) {
	if got := NewMessageContext().ThreatVerdict(); got != "unknown" {
		t.Fatalf("ThreatVerdict() = %q", got)
	}
}

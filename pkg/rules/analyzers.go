package rules

// AnalyzerFinding is one explainable observation produced by an external
// analyzer. Code is the stable policy-facing identifier; Summary is intended
// for logs and accessible reports.
type AnalyzerFinding struct {
	Source     string  `json:"source,omitempty"`
	Code       string  `json:"code"`
	Summary    string  `json:"summary"`
	Severity   string  `json:"severity,omitempty"`
	Confidence float64 `json:"confidence,omitempty"`
	Attachment string  `json:"attachment,omitempty"`
}

// AnalyzerResult is the shared sidecar response contract. Score is a risk
// score from 0 to 1, rather than confidence in a possibly-clean verdict.
type AnalyzerResult struct {
	Analyzer     string            `json:"analyzer"`
	Verdict      string            `json:"verdict"`
	Score        float64           `json:"score"`
	Categories   []string          `json:"categories,omitempty"`
	Findings     []AnalyzerFinding `json:"findings,omitempty"`
	IOCs         []string          `json:"iocs,omitempty"`
	ModelVersion string            `json:"model_version,omitempty"`
	Deferred     bool              `json:"deferred,omitempty"`
}

// ThreatVerdict returns the most severe analyzer verdict. An inconclusive
// result outranks clean so a failed or uncertain analysis cannot become clean.
func (m *MessageContext) ThreatVerdict() string {
	rank := map[string]int{"clean": 1, "unknown": 2, "suspicious": 3, "malicious": 4}
	verdict, best := "unknown", 0
	for _, result := range m.AnalyzerResults {
		if rank[result.Verdict] > best {
			verdict, best = result.Verdict, rank[result.Verdict]
		}
	}
	return verdict
}

func (m *MessageContext) ThreatScore() float64 {
	var score float64
	for _, result := range m.AnalyzerResults {
		if result.Score > score {
			score = result.Score
		}
	}
	return score
}

func (m *MessageContext) AnalysisPending() bool {
	for _, result := range m.AnalyzerResults {
		if result.Deferred {
			return true
		}
	}
	return false
}

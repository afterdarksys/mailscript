package rules

import (
	"fmt"
	"strconv"
	"strings"
)

// AIAssessment reports evidence that an email was composed or dispatched by
// an AI agent. It deliberately avoids pretending prose-style detection is
// reliable: only provenance and sending-system signals contribute.
type AIAssessment struct {
	Score   float64
	Class   string
	Reasons []string
}

// AssessAI evaluates explicit and infrastructure-level AI provenance.
func (m *MessageContext) AssessAI() AIAssessment {
	out := AIAssessment{Class: "unknown"}
	set := func(score float64, reason string) {
		if score > out.Score {
			out.Score = score
		}
		out.Reasons = append(out.Reasons, reason)
	}

	for _, name := range []string{"AI-Generated", "X-AI-Generated", "X-AI-Authored", "X-AI-Agent"} {
		if value := strings.TrimSpace(m.Get(name)); value != "" {
			lower := strings.ToLower(value)
			if lower == "yes" || lower == "true" || lower == "1" || lower == "generated" || name == "X-AI-Agent" {
				set(100, fmt.Sprintf("%s explicitly declares AI generation", name))
			}
		}
	}

	producer := strings.ToLower(strings.Join([]string{
		m.Get("X-Generated-By"), m.Get("X-Mailer"), m.Get("User-Agent"), m.Get("X-Agent"),
	}, " "))
	for _, marker := range []string{
		"openai", "chatgpt", "anthropic", "claude", "gemini", "copilot",
		"langchain", "autogen", "crewai", "mail-ai", "ai-agent",
	} {
		if strings.Contains(producer, marker) {
			set(85, fmt.Sprintf("sending software identifies AI system %q", marker))
			break
		}
	}

	// RFC-style comments sometimes encode a fractional confidence supplied by
	// a trusted upstream detector. We accept it only as another signal; policy
	// authors remain responsible for trusting the header's insertion point.
	if raw := strings.TrimSpace(m.Get("X-AI-Probability")); raw != "" {
		if probability, err := strconv.ParseFloat(raw, 64); err == nil && probability >= 0 && probability <= 1 {
			set(probability*100, "upstream X-AI-Probability="+raw)
		}
	}

	switch {
	case out.Score >= 95:
		out.Class = "declared"
	case out.Score >= 70:
		out.Class = "likely"
	case out.Score > 0:
		out.Class = "possible"
	}
	return out
}

// IsAIGenerated applies the default high-confidence policy threshold.
func (m *MessageContext) IsAIGenerated() bool { return m.AssessAI().Score >= 70 }

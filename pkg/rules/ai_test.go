package rules

import "testing"

func TestAssessAIExplicitProvenance(t *testing.T) {
	ctx, err := ParseMessage([]byte("From: bot@example.com\r\nX-AI-Generated: yes\r\n\r\nHello\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := ctx.AssessAI()
	if got.Score != 100 || got.Class != "declared" || !ctx.IsAIGenerated() {
		t.Fatalf("unexpected assessment: %+v", got)
	}
}

func TestAssessAIDoesNotGuessFromProse(t *testing.T) {
	ctx, err := ParseMessage([]byte("From: person@example.com\r\n\r\nIn conclusion, I hope this email finds you well.\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if got := ctx.AssessAI(); got.Score != 0 || got.Class != "unknown" {
		t.Fatalf("prose alone must not be labeled AI: %+v", got)
	}
}

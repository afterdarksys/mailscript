package rules

import (
	"strings"
	"testing"
)

func TestFieldPrimitives(t *testing.T) {
	m := mustParse(t, "Subject: Invoice 123\r\nX-Label: banana\r\nx-label: banana\r\nBody: literal header\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nY2Fmw6kgY2Fmw6k=\r\n")
	m.EnvelopeTo = []string{"one@example.com", "two@example.org"}
	script := `
def check(value):
    if not value:
        fail("field assertion failed")
check(contains(field="SUBJECT", substring="Invoice"))
check(not contains("subject", "invoice"))
check(contains("body", "café"))
check(contains("header:Body", "literal header"))
check(not contains("X-Missing", ""))
check(contains("envelope_to", "example.org"))
check(matches_regex(field="Subject", pattern="(?i)^invoice [0-9]+$"))
check(not matches_regex("x-label", "banana.*banana"))
check(count_occurrences("x-label", "ana") == 2)
check(count_occurrences(field="body", substring="café") == 2)
check(count_occurrences("missing", "x") == 0)
check(not matches_regex("missing", ".*"))
`
	if err := ExecuteEngine(script, m); err != nil {
		t.Fatal(err)
	}
}

func TestFieldPrimitiveErrors(t *testing.T) {
	for _, script := range []string{
		`matches_regex("Missing", "[")`, `contains("bad field", "x")`,
		`count_occurrences("body", "")`, `has_language("xx")`,
		`has_language(42)`, `contains("body", 42)`, `contains("", "x")`,
	} {
		if err := ExecuteEngine(script, NewMessageContext()); err == nil {
			t.Errorf("expected error from %s", script)
		}
	}
}

func TestLanguagePrimitive(t *testing.T) {
	const english = "This is an English message about the meeting tomorrow. Please review the attached report and send your comments to the team before the end of the working day. We will discuss the results and make a decision together."
	const french = "Bonjour, voici un message écrit en français pour expliquer les résultats de notre réunion. Nous vous remercions de votre participation et nous vous invitons à nous envoyer vos commentaires avant la fin de la semaine."
	for _, tc := range []struct{ name, raw, script string }{
		{"english", "Content-Language: fr\r\n\r\n" + english, `has_language("en") and has_language("ENG") and not has_language("fr")`},
		{"french_html", "Content-Type: text/html; charset=utf-8\r\n\r\n<p>" + french + "</p>", `has_language("fr") and not has_language("en")`},
		{"french_latin1", "Content-Type: text/plain; charset=iso-8859-1\r\n\r\n" + strings.ReplaceAll(strings.ReplaceAll(french, "é", "\xe9"), "à", "\xe0"), `has_language("fr")`},
		{"sample_limit", "Content-Type: text/plain\r\n\r\n" + strings.Repeat(" ", 64*1024) + english, `not has_language("en")`},
		{"short", "\r\nHello", `not has_language("en")`},
		{"empty", "Content-Language: en\r\n\r\n", `not has_language("en")`},
		{"attachment", "Content-Type: text/plain\r\nContent-Disposition: attachment; filename=note.txt\r\n\r\n" + english, `not has_language("en")`},
		{"multipart", "Content-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\nContent-Type: text/plain\r\n\r\n" + english + "\r\n--x\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + french + "\r\n--x--\r\n", `has_language("en") and has_language("fr")`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := mustParse(t, tc.raw)
			if err := ExecuteEngine("def evaluate():\n    if not ("+tc.script+"):\n        fail(\"language assertion failed\")", m); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAttachmentTypesPrimitive(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"Subject: no attachments\r\n\r\nhello", "[]"},
		{"Content-Type: APPLICATION/PDF\r\nContent-Disposition: attachment; filename=report.pdf\r\n\r\nPDF", `["application/pdf"]`},
		{"Content-Disposition: attachment; filename=note.txt\r\n\r\nhello", `["text/plain"]`},
		{"Content-Type: image/png; name=logo.png\r\nContent-Disposition: inline\r\n\r\nPNG", `["image/png"]`},
		{"Content-Type: multipart/mixed; boundary=x\r\n\r\n" + strings.Repeat("--x\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=x.pdf\r\n\r\nPDF\r\n", 2) + "--x--\r\n", `["application/pdf", "application/pdf"]`},
	} {
		m := mustParse(t, tc.raw)
		if err := ExecuteEngine("def evaluate():\n    if attachment_types() != "+tc.want+":\n        fail(str(attachment_types()))", m); err != nil {
			t.Fatal(err)
		}
	}
}

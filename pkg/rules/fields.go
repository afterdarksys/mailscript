package rules

import (
	"fmt"
	"html"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/abadojack/whatlanggo"
	"go.starlark.net/starlark"
	"golang.org/x/net/html/charset"
)

// fieldValues resolves selectors, never guesses whether a string is literal
// text. Header occurrences remain separate so matches cannot cross fields.
func (m *MessageContext) fieldValues(field string) ([]string, error) {
	key := strings.ToLower(field)
	if strings.HasPrefix(key, "header:") {
		field = field[len("header:"):]
	} else {
		switch key {
		case "body":
			return []string{m.SearchText()}, nil
		case "text_body":
			return []string{m.TextBody}, nil
		case "html_body":
			return []string{m.HTMLBody}, nil
		case "raw_body":
			return []string{m.Body}, nil
		case "envelope_from":
			return []string{m.EnvelopeFrom}, nil
		case "envelope_to":
			return m.EnvelopeTo, nil
		}
	}
	if field == "" {
		return nil, fmt.Errorf("field must name a header or message field")
	}
	for _, c := range field {
		if c < 33 || c > 126 || c == ':' {
			return nil, fmt.Errorf("invalid header field %q", field)
		}
	}
	return m.GetAll(field), nil
}

func (e *scriptEnv) fieldBuiltins() starlark.StringDict {
	var languages map[whatlanggo.Lang]bool
	return starlark.StringDict{
		"contains": binary("contains", "field", "substring", func(field, substring string) (starlark.Value, error) {
			values, err := e.msg.fieldValues(field)
			if err != nil {
				return nil, err
			}
			for _, value := range values {
				if strings.Contains(value, substring) {
					return starlark.True, nil
				}
			}
			return starlark.False, nil
		}),
		"matches_regex": binary("matches_regex", "field", "pattern", func(field, pattern string) (starlark.Value, error) {
			re, err := CompileRegex(pattern)
			if err != nil {
				return nil, fmt.Errorf("matches_regex: %w", err)
			}
			values, err := e.msg.fieldValues(field)
			if err != nil {
				return nil, err
			}
			for _, value := range values {
				if re.MatchString(value) {
					return starlark.True, nil
				}
			}
			return starlark.False, nil
		}),
		"count_occurrences": binary("count_occurrences", "field", "substring", func(field, substring string) (starlark.Value, error) {
			if substring == "" {
				return nil, fmt.Errorf("count_occurrences: substring must not be empty")
			}
			values, err := e.msg.fieldValues(field)
			if err != nil {
				return nil, err
			}
			count := 0
			for _, value := range values {
				count += strings.Count(value, substring)
			}
			return starlark.MakeInt(count), nil
		}),
		"has_language": starlark.NewBuiltin("has_language", func(_ *starlark.Thread, _ *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
			var code string
			if err := starlark.UnpackArgs("has_language", args, kwargs, "lang_code", &code); err != nil {
				return nil, err
			}
			code = strings.ToLower(code)
			lang := whatlanggo.Lang(-1)
			for candidate := whatlanggo.Afr; candidate <= whatlanggo.Zul; candidate++ {
				if code != "" && (candidate.Iso6391() == code || candidate.Iso6393() == code) {
					lang = candidate
					break
				}
			}
			if lang < 0 {
				return nil, fmt.Errorf("has_language: unsupported ISO 639 language code %q", code)
			}
			if languages == nil {
				languages = e.msg.detectLanguages()
			}
			return starlark.Bool(languages[lang]), nil
		}),
	}
}

// Detection is bounded and cached once per evaluation. It deliberately ignores
// Content-Language declarations, which are sender-controlled assertions.
func (m *MessageContext) detectLanguages() map[whatlanggo.Lang]bool {
	found := make(map[whatlanggo.Lang]bool)
	remaining := 64 * 1024
	sampled := 0
	parts := m.Parts
	if len(parts) == 0 {
		parts = []MIMEPart{{ContentType: "text/plain", Content: m.TextBody}, {ContentType: "text/html", Content: m.HTMLBody}}
	}
	for _, part := range parts {
		if remaining <= 0 || sampled >= 64 {
			break
		}
		if part.Disposition == "attachment" || part.Content == "" || (part.ContentType != "text/plain" && part.ContentType != "text/html") {
			continue
		}
		sampled++
		text := part.Content
		if len(text) > remaining {
			text = text[:remaining]
		}
		remaining -= len(text)
		if part.Charset != "" {
			reader, err := charset.NewReaderLabel(part.Charset, strings.NewReader(text))
			if err != nil {
				continue
			}
			decoded, err := io.ReadAll(io.LimitReader(reader, 256*1024))
			if err != nil {
				continue
			}
			text = string(decoded)
		}
		text = strings.ToValidUTF8(text, " ")
		if part.ContentType == "text/html" {
			text = html.UnescapeString(tagPattern.ReplaceAllString(text, " "))
		}
		letters := 0
		for _, r := range text {
			if unicode.IsLetter(r) && r != utf8.RuneError {
				letters++
			}
		}
		if letters < 20 {
			continue
		}
		info := whatlanggo.Detect(text)
		if info.IsReliable() {
			found[info.Lang] = true
		}
	}
	return found
}

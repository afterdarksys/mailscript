// Package ml provides the text-classification machinery MailScript rules use
// to score messages: a mail-aware analyzer, a TF-IDF vectorizer, a
// multinomial Naive Bayes classifier, and a WordPiece tokenizer for
// BERT-style feature extraction.
//
// Everything here is pure Go with no external dependencies, so a rule can
// classify a message in the SMTP path without adding measurable latency.
// Heavier algorithms are available behind the "golearn" build tag, and
// transformer embeddings can be supplied through the Embedder interface.
package ml

import (
	"regexp"
	"strings"
	"unicode"
)

// Analyzer turns a message into the token sequence a model is trained on.
//
// It is mail-aware in three ways that matter for spam classification:
// URLs and addresses collapse to their host, so a campaign that randomises
// paths still produces a stable feature; runs of punctuation and currency
// symbols survive tokenisation, because "!!!" and "$$$" carry signal; and
// casing is recorded as a separate feature rather than discarded, since
// SHOUTING is itself predictive.
type Analyzer struct {
	Lowercase   bool
	StripHTML   bool
	MinLen      int
	MaxLen      int
	NGramMin    int // smallest n-gram to emit, 1 for unigrams
	NGramMax    int // largest n-gram to emit
	Stopwords   map[string]bool
	MaxTokens   int  // 0 means unlimited
	KeepNumbers bool // when false, numbers collapse to a NUM placeholder
	// OSBWindow emits orthogonal sparse-bigram features up to this distance.
	// Zero disables them; 5 is a practical order-sensitive spam setting.
	OSBWindow int
}

// DefaultAnalyzer returns the analyzer used when a model does not specify one.
func DefaultAnalyzer() *Analyzer {
	return &Analyzer{
		Lowercase:   true,
		StripHTML:   true,
		MinLen:      2,
		MaxLen:      32,
		NGramMin:    1,
		NGramMax:    2,
		Stopwords:   EnglishStopwords(),
		MaxTokens:   20000,
		KeepNumbers: false,
	}
}

var (
	analyzerTagPattern   = regexp.MustCompile(`(?s)<[^>]*>`)
	analyzerURLPattern   = regexp.MustCompile(`(?i)\b(?:https?|ftp)://[^\s<>"']+`)
	analyzerEmailPattern = regexp.MustCompile(`(?i)\b[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}\b`)
	analyzerHostPattern  = regexp.MustCompile(`(?i)^(?:https?|ftp)://(?:[^@/]*@)?([^/:?#]+)`)
	analyzerNumPattern   = regexp.MustCompile(`^[\d.,]+$`)
	analyzerMoneyPattern = regexp.MustCompile(`[$€£¥₹]\s?[\d,]+(?:\.\d{2})?`)
	// Go's regexp is RE2 and has no backreferences, so each repeated
	// character class is spelled out rather than written as ([!?$*#])\1+.
	analyzerPunctRun = regexp.MustCompile(`!{2,}|\?{2,}|\${2,}|\*{2,}|#{2,}`)
)

// punctMarkerNames maps an emphasis character to the alphabetic name used in
// its feature marker.
var punctMarkerNames = map[byte]string{
	'!': "bang",
	'?': "query",
	'$': "cash",
	'*': "star",
	'#': "hash",
}

// Analyze produces the token sequence for a document.
func (a *Analyzer) Analyze(text string) []string {
	if a == nil {
		a = DefaultAnalyzer()
	}
	if text == "" {
		return nil
	}

	if a.StripHTML {
		text = analyzerTagPattern.ReplaceAllString(text, " ")
	}

	var special []string

	// Collapse URLs to their host so randomised paths do not fragment the
	// feature space, and keep the host itself as a feature.
	text = analyzerURLPattern.ReplaceAllStringFunc(text, func(u string) string {
		if match := analyzerHostPattern.FindStringSubmatch(u); len(match) == 2 {
			special = append(special, "url:"+strings.ToLower(match[1]))
		}
		return " __url__ "
	})

	text = analyzerEmailPattern.ReplaceAllStringFunc(text, func(e string) string {
		if at := strings.LastIndex(e, "@"); at >= 0 {
			special = append(special, "emaildom:"+strings.ToLower(e[at+1:]))
		}
		return " __email__ "
	})

	for _, money := range analyzerMoneyPattern.FindAllString(text, -1) {
		_ = money
		special = append(special, "__money__")
	}

	// Runs of emphasis punctuation collapse to a single marker per kind. The
	// marker must be alphabetic: splitWords discards punctuation, so a
	// marker containing the character it stands for would not survive
	// tokenisation.
	text = analyzerPunctRun.ReplaceAllStringFunc(text, func(run string) string {
		return " __rep" + punctMarkerNames[run[0]] + "__ "
	})

	unigrams := make([]string, 0, 64)
	unigrams = append(unigrams, special...)

	for _, raw := range splitWords(text) {
		token := raw
		if a.Lowercase {
			// Record shouting before the case information is destroyed.
			if len([]rune(raw)) >= 4 && raw == strings.ToUpper(raw) && hasLetter(raw) {
				unigrams = append(unigrams, "__caps__")
			}
			token = strings.ToLower(token)
		}

		token = strings.Trim(token, "'\"`.,;:")
		if token == "" {
			continue
		}

		if !a.KeepNumbers && analyzerNumPattern.MatchString(token) {
			token = "__num__"
		}

		runeLen := len([]rune(token))
		if !strings.HasPrefix(token, "__") {
			if a.MinLen > 0 && runeLen < a.MinLen {
				continue
			}
			if a.MaxLen > 0 && runeLen > a.MaxLen {
				continue
			}
			if a.Stopwords != nil && a.Stopwords[token] {
				continue
			}
		}

		unigrams = append(unigrams, token)
		if a.MaxTokens > 0 && len(unigrams) >= a.MaxTokens {
			break
		}
	}

	out := a.expandNGrams(unigrams)
	if a.OSBWindow > 1 {
		for i := 0; i < len(unigrams); i++ {
			end := i + a.OSBWindow
			if end >= len(unigrams) {
				end = len(unigrams) - 1
			}
			for j := i + 1; j <= end; j++ {
				out = append(out, unigrams[i]+"~"+string(rune('0'+minIntML(j-i, 9)))+"~"+unigrams[j])
			}
		}
	}
	return out
}

func minIntML(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// expandNGrams emits the configured range of n-grams over a unigram sequence.
func (a *Analyzer) expandNGrams(unigrams []string) []string {
	nMin, nMax := a.NGramMin, a.NGramMax
	if nMin < 1 {
		nMin = 1
	}
	if nMax < nMin {
		nMax = nMin
	}
	if nMin == 1 && nMax == 1 {
		return unigrams
	}

	out := make([]string, 0, len(unigrams)*(nMax-nMin+1))
	for n := nMin; n <= nMax; n++ {
		if n == 1 {
			out = append(out, unigrams...)
			continue
		}
		for i := 0; i+n <= len(unigrams); i++ {
			out = append(out, strings.Join(unigrams[i:i+n], "_"))
		}
	}
	return out
}

// splitWords splits on any character that is not a letter, digit, underscore,
// apostrophe or hyphen.
func splitWords(text string) []string {
	return strings.FieldsFunc(text, func(r rune) bool {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return false
		}
		switch r {
		case '_', '\'', '-':
			return false
		}
		return true
	})
}

func hasLetter(s string) bool {
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

// EnglishStopwords returns a compact stopword set. It is intentionally small:
// aggressive stopword removal hurts spam classification, because function
// words carry style signal that distinguishes written prose from generated
// copy.
func EnglishStopwords() map[string]bool {
	words := []string{
		"a", "an", "and", "are", "as", "at", "be", "by", "for", "from",
		"has", "he", "in", "is", "it", "its", "of", "on", "that", "the",
		"to", "was", "were", "will", "with", "or", "but", "if", "then",
		"this", "these", "those", "there", "their", "them", "they",
	}
	set := make(map[string]bool, len(words))
	for _, w := range words {
		set[w] = true
	}
	return set
}

// TokenCounts reduces a token sequence to term frequencies.
func TokenCounts(tokens []string) map[string]int {
	counts := make(map[string]int, len(tokens))
	for _, t := range tokens {
		counts[t]++
	}
	return counts
}

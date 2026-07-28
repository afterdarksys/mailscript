package rules

import (
	"strings"
	"unicode"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// RegisteredDomain returns the organisational domain (eTLD+1) for a hostname,
// using the Public Suffix List. It is what DMARC relaxed alignment compares,
// and it is why "mail.example.co.uk" and "example.co.uk" are the same
// organisation while "example.co.uk" and "evil.co.uk" are not.
//
// Input that is not a hostname, or a hostname that is itself a public suffix,
// is returned lowercased and unchanged.
func RegisteredDomain(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	etld1, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return host
	}
	return etld1
}

// PublicSuffix returns the public suffix of a hostname (for example "co.uk").
func PublicSuffix(host string) string {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return ""
	}
	suffix, _ := publicsuffix.PublicSuffix(host)
	return suffix
}

// SameOrgDomain reports whether two hostnames share an organisational domain.
func SameOrgDomain(a, b string) bool {
	ra, rb := RegisteredDomain(a), RegisteredDomain(b)
	return ra != "" && ra == rb
}

// IsSubdomainOf reports whether host is child, or a subdomain of, parent.
func IsSubdomainOf(host, parent string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	parent = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(parent), "."))
	if host == "" || parent == "" {
		return false
	}
	return host == parent || strings.HasSuffix(host, "."+parent)
}

// ToUnicodeDomain converts a punycode domain to its Unicode form, which is
// what a recipient actually sees and therefore what homoglyph checks must
// operate on. Undecodable input is returned unchanged.
func ToUnicodeDomain(host string) string {
	if !strings.Contains(host, "xn--") {
		return host
	}
	decoded, err := idna.ToUnicode(host)
	if err != nil {
		return host
	}
	return decoded
}

// ToASCIIDomain converts a Unicode domain to its punycode form.
func ToASCIIDomain(host string) string {
	encoded, err := idna.ToASCII(host)
	if err != nil {
		return host
	}
	return encoded
}

// scriptTable pairs a Unicode script with the name reported to rules.
var scriptTable = []struct {
	name  string
	table *unicode.RangeTable
}{
	{"Latin", unicode.Latin},
	{"Cyrillic", unicode.Cyrillic},
	{"Greek", unicode.Greek},
	{"Han", unicode.Han},
	{"Hiragana", unicode.Hiragana},
	{"Katakana", unicode.Katakana},
	{"Hangul", unicode.Hangul},
	{"Arabic", unicode.Arabic},
	{"Hebrew", unicode.Hebrew},
	{"Cherokee", unicode.Cherokee},
	{"Armenian", unicode.Armenian},
	{"Devanagari", unicode.Devanagari},
	{"Thai", unicode.Thai},
}

// ScriptsIn returns the names of the Unicode scripts present in a string,
// ignoring digits, punctuation and other script-neutral characters.
func ScriptsIn(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, r := range s {
		if r < unicode.MaxASCII && !unicode.IsLetter(r) {
			continue
		}
		if unicode.IsDigit(r) || unicode.IsSpace(r) || unicode.IsPunct(r) || unicode.IsSymbol(r) {
			continue
		}
		for _, entry := range scriptTable {
			if unicode.Is(entry.table, r) {
				if !seen[entry.name] {
					seen[entry.name] = true
					out = append(out, entry.name)
				}
				break
			}
		}
	}
	return out
}

// IsMixedScript reports whether a string mixes Unicode scripts in a way that
// is characteristic of homoglyph attacks, for example Latin "paypal" with a
// Cyrillic "а". Japanese text legitimately mixes Han, Hiragana and Katakana,
// and Korean mixes Han and Hangul, so those combinations are not flagged.
func IsMixedScript(s string) bool {
	scripts := ScriptsIn(s)
	if len(scripts) < 2 {
		return false
	}

	set := map[string]bool{}
	for _, s := range scripts {
		set[s] = true
	}

	// Collapse the writing systems that are normally used together.
	if set["Han"] || set["Hiragana"] || set["Katakana"] {
		delete(set, "Hiragana")
		delete(set, "Katakana")
		if set["Hangul"] {
			delete(set, "Han")
		}
	}
	if set["Hangul"] {
		delete(set, "Han")
	}

	return len(set) > 1
}

// confusables maps characters that render like ASCII letters to the letter
// they imitate. It is deliberately limited to the high-frequency homoglyphs
// used in domain and display-name spoofing rather than the full Unicode
// confusables table, which is large and mostly irrelevant to email.
var confusables = map[rune]rune{
	'а': 'a', 'ᴀ': 'a', 'ɑ': 'a', 'α': 'a', 'ａ': 'a',
	'ь': 'b', 'Ь': 'b', 'ｂ': 'b', 'ḅ': 'b',
	'с': 'c', 'ϲ': 'c', 'ᴄ': 'c', 'ｃ': 'c',
	'ԁ': 'd', 'ⅾ': 'd', 'ｄ': 'd',
	'е': 'e', 'ҽ': 'e', 'ᴇ': 'e', 'ｅ': 'e', 'ё': 'e',
	'ｆ': 'f', 'ḟ': 'f',
	'ɡ': 'g', 'ց': 'g', 'ｇ': 'g',
	'һ': 'h', 'ｈ': 'h', 'ḥ': 'h',
	// The l/I/1/i family all render near-identically in most fonts, so every
	// member folds to the same target. Folding must be single-pass
	// consistent: no variant may map to another key in this table.
	'і': 'i', 'ı': 'i', 'ɩ': 'i', 'ｉ': 'i', 'ⅰ': 'i',
	'l': 'i', 'ⅼ': 'i', 'ｌ': 'i', 'ӏ': 'i', 'Ɩ': 'i', '1': 'i', '|': 'i',
	'ϳ': 'j', 'ј': 'j', 'ｊ': 'j',
	'κ': 'k', 'ｋ': 'k',
	'м': 'm', 'ｍ': 'm', 'ⅿ': 'm',
	'п': 'n', 'ｎ': 'n', 'ɴ': 'n',
	'о': 'o', 'ο': 'o', 'σ': 'o', 'ｏ': 'o', 'ᴏ': 'o', '0': 'o',
	'р': 'p', 'ρ': 'p', 'ｐ': 'p',
	'ԛ': 'q', 'ｑ': 'q',
	'г': 'r', 'ｒ': 'r', 'ꭇ': 'r',
	'ѕ': 's', 'ｓ': 's', 'ꜱ': 's',
	'т': 't', 'τ': 't', 'ｔ': 't',
	'υ': 'u', 'ᴜ': 'u', 'ｕ': 'u', 'ս': 'u',
	'ν': 'v', 'ѵ': 'v', 'ｖ': 'v', 'ⅴ': 'v',
	'ԝ': 'w', 'ѡ': 'w', 'ｗ': 'w',
	'х': 'x', 'χ': 'x', 'ｘ': 'x', 'ⅹ': 'x',
	'у': 'y', 'γ': 'y', 'ｙ': 'y',
	'ᴢ': 'z', 'ｚ': 'z',
}

// Skeleton reduces a string to a comparison form in which common homoglyphs
// have been folded to the ASCII letter they imitate. Two strings with the
// same skeleton look alike to a human reader even if their bytes differ.
func Skeleton(s string) string {
	var sb strings.Builder
	for _, r := range strings.ToLower(s) {
		if mapped, ok := confusables[r]; ok {
			sb.WriteRune(mapped)
			continue
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

// LooksLike reports whether candidate is a homoglyph or typo imitation of
// target without being an exact match. It catches both confusable
// substitution ("pаypal.com" with a Cyrillic a) and single-character typos
// ("paypaI.com", "payppal.com").
func LooksLike(candidate, target string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	target = strings.ToLower(strings.TrimSpace(target))
	if candidate == "" || target == "" || candidate == target {
		return false
	}
	if Skeleton(candidate) == Skeleton(target) {
		return true
	}
	// Allow one edit for short names, two for longer ones, so that
	// "microsoft" tolerates a typo but "abc" does not match everything.
	maxEdits := 1
	if len(target) > 12 {
		maxEdits = 2
	}
	return levenshtein(Skeleton(candidate), Skeleton(target)) <= maxEdits
}

// levenshtein computes the edit distance between two strings using a
// single-row dynamic programming table.
func levenshtein(a, b string) int {
	ra, rb := []rune(a), []rune(b)
	if len(ra) == 0 {
		return len(rb)
	}
	if len(rb) == 0 {
		return len(ra)
	}

	prev := make([]int, len(rb)+1)
	cur := make([]int, len(rb)+1)
	for j := range prev {
		prev[j] = j
	}

	for i := 1; i <= len(ra); i++ {
		cur[0] = i
		for j := 1; j <= len(rb); j++ {
			cost := 1
			if ra[i-1] == rb[j-1] {
				cost = 0
			}
			cur[j] = minInt(cur[j-1]+1, minInt(prev[j]+1, prev[j-1]+cost))
		}
		prev, cur = cur, prev
	}
	return prev[len(rb)]
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

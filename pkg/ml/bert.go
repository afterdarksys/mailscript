package ml

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strings"
	"unicode"
)

// Special tokens used by BERT-family vocabularies.
const (
	TokenUnknown       = "[UNK]"
	TokenClassifier    = "[CLS]"
	TokenSeparator     = "[SEP]"
	TokenPad           = "[PAD]"
	TokenMask          = "[MASK]"
	subwordPrefix      = "##"
	defaultMaxWordSize = 100
)

// BertTokenizer implements the WordPiece tokenization that BERT-family models
// expect: basic tokenization (accent stripping, punctuation splitting, CJK
// isolation) followed by greedy longest-match subword segmentation against a
// fixed vocabulary.
//
// This produces the token IDs a transformer consumes. It performs no
// inference on its own; pair it with an Embedder when a model is available.
// On its own it is still useful as a feature extractor, because WordPiece
// segments out-of-vocabulary words into meaningful subwords where a
// whitespace tokenizer would emit a single unknown term.
type BertTokenizer struct {
	vocab     map[string]int
	ids       []string
	lowercase bool
	// MaxInputCharsPerWord caps subword search on pathologically long tokens.
	MaxInputCharsPerWord int
}

// NewBertTokenizer builds a tokenizer from an ordered vocabulary, where the
// index of each entry is its token ID.
func NewBertTokenizer(vocab []string, lowercase bool) *BertTokenizer {
	index := make(map[string]int, len(vocab))
	for i, token := range vocab {
		if _, exists := index[token]; !exists {
			index[token] = i
		}
	}
	return &BertTokenizer{
		vocab:                index,
		ids:                  vocab,
		lowercase:            lowercase,
		MaxInputCharsPerWord: defaultMaxWordSize,
	}
}

// LoadBertVocab reads a vocab.txt file, one token per line, as shipped with
// every BERT checkpoint.
func LoadBertVocab(path string, lowercase bool) (*BertTokenizer, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ml: open BERT vocabulary: %w", err)
	}
	defer file.Close()

	var vocab []string
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		vocab = append(vocab, strings.TrimRight(scanner.Text(), "\r\n"))
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("ml: read BERT vocabulary: %w", err)
	}
	if len(vocab) == 0 {
		return nil, fmt.Errorf("ml: BERT vocabulary %q is empty", path)
	}

	return NewBertTokenizer(vocab, lowercase), nil
}

// Size returns the vocabulary size.
func (t *BertTokenizer) Size() int {
	if t == nil {
		return 0
	}
	return len(t.ids)
}

// Tokenize returns the WordPiece tokens for a text.
func (t *BertTokenizer) Tokenize(text string) []string {
	if t == nil || len(t.vocab) == 0 {
		return nil
	}

	var out []string
	for _, word := range t.basicTokenize(text) {
		out = append(out, t.wordpiece(word)...)
	}
	return out
}

// Encode returns the token IDs for a text, optionally wrapped in the [CLS]
// and [SEP] markers a classification head expects, and truncated or padded to
// maxLen when maxLen is positive.
func (t *BertTokenizer) Encode(text string, addSpecial bool, maxLen int) []int {
	tokens := t.Tokenize(text)

	if addSpecial {
		limit := maxLen - 2
		if maxLen > 0 && len(tokens) > limit && limit >= 0 {
			tokens = tokens[:limit]
		}
		tokens = append([]string{TokenClassifier}, append(tokens, TokenSeparator)...)
	} else if maxLen > 0 && len(tokens) > maxLen {
		tokens = tokens[:maxLen]
	}

	ids := make([]int, 0, len(tokens))
	unk := t.id(TokenUnknown)
	for _, token := range tokens {
		if id, ok := t.vocab[token]; ok {
			ids = append(ids, id)
			continue
		}
		ids = append(ids, unk)
	}

	if maxLen > 0 {
		pad := t.id(TokenPad)
		for len(ids) < maxLen {
			ids = append(ids, pad)
		}
	}
	return ids
}

// AttentionMask returns the mask matching an Encode call: 1 for real tokens,
// 0 for padding.
func (t *BertTokenizer) AttentionMask(ids []int) []int {
	pad := t.id(TokenPad)
	mask := make([]int, len(ids))
	for i, id := range ids {
		if id != pad {
			mask[i] = 1
		}
	}
	return mask
}

// Decode converts token IDs back to text, rejoining subword pieces.
func (t *BertTokenizer) Decode(ids []int) string {
	var sb strings.Builder
	for _, id := range ids {
		if id < 0 || id >= len(t.ids) {
			continue
		}
		token := t.ids[id]
		switch token {
		case TokenPad, TokenClassifier, TokenSeparator:
			continue
		}
		if strings.HasPrefix(token, subwordPrefix) {
			sb.WriteString(token[len(subwordPrefix):])
			continue
		}
		if sb.Len() > 0 {
			sb.WriteByte(' ')
		}
		sb.WriteString(token)
	}
	return sb.String()
}

func (t *BertTokenizer) id(token string) int {
	if id, ok := t.vocab[token]; ok {
		return id
	}
	return 0
}

// basicTokenize splits on whitespace and punctuation, isolates CJK
// characters, and optionally lowercases and strips accents.
func (t *BertTokenizer) basicTokenize(text string) []string {
	var out []string

	for _, chunk := range strings.Fields(text) {
		if t.lowercase {
			chunk = strings.ToLower(stripAccents(chunk))
		}

		var cur strings.Builder
		flush := func() {
			if cur.Len() > 0 {
				out = append(out, cur.String())
				cur.Reset()
			}
		}

		for _, r := range chunk {
			switch {
			case isControlRune(r):
				// Control characters carry no meaning; drop them.
			case isPunctuationRune(r):
				flush()
				out = append(out, string(r))
			case isCJKRune(r):
				// Each CJK character is its own token, as BERT expects.
				flush()
				out = append(out, string(r))
			default:
				cur.WriteRune(r)
			}
		}
		flush()
	}

	return out
}

// wordpiece performs greedy longest-match-first subword segmentation.
func (t *BertTokenizer) wordpiece(word string) []string {
	runes := []rune(word)
	if len(runes) == 0 {
		return nil
	}
	if t.MaxInputCharsPerWord > 0 && len(runes) > t.MaxInputCharsPerWord {
		return []string{TokenUnknown}
	}

	var pieces []string
	start := 0
	for start < len(runes) {
		end := len(runes)
		var match string

		for start < end {
			candidate := string(runes[start:end])
			if start > 0 {
				candidate = subwordPrefix + candidate
			}
			if _, ok := t.vocab[candidate]; ok {
				match = candidate
				break
			}
			end--
		}

		if match == "" {
			// No prefix of the remaining word is in the vocabulary, so the
			// whole word is unknown; WordPiece does not emit partial results.
			return []string{TokenUnknown}
		}

		pieces = append(pieces, match)
		start = end
	}

	return pieces
}

func stripAccents(s string) string {
	var sb strings.Builder
	for _, r := range s {
		if unicode.Is(unicode.Mn, r) {
			continue // non-spacing mark
		}
		sb.WriteRune(r)
	}
	return sb.String()
}

func isControlRune(r rune) bool {
	if r == '\t' || r == '\n' || r == '\r' {
		return false
	}
	return unicode.IsControl(r) || r == 0xFFFD
}

func isPunctuationRune(r rune) bool {
	// BERT treats every non-alphanumeric ASCII character as punctuation, in
	// addition to the Unicode punctuation categories.
	if r <= unicode.MaxASCII && !unicode.IsLetter(r) && !unicode.IsDigit(r) && !unicode.IsSpace(r) {
		return true
	}
	return unicode.IsPunct(r)
}

func isCJKRune(r rune) bool {
	switch {
	case r >= 0x4E00 && r <= 0x9FFF,
		r >= 0x3400 && r <= 0x4DBF,
		r >= 0x20000 && r <= 0x2A6DF,
		r >= 0x2A700 && r <= 0x2B73F,
		r >= 0x2B740 && r <= 0x2B81F,
		r >= 0x2B820 && r <= 0x2CEAF,
		r >= 0xF900 && r <= 0xFAFF,
		r >= 0x2F800 && r <= 0x2FA1F:
		return true
	}
	return false
}

// Embedder produces a dense vector for a text. It is the extension point for
// transformer embeddings: implement it against an ONNX runtime, a remote
// inference service, or any other backend, then register it so rule scripts
// can call embed() and embed_similarity().
//
// No implementation ships with MailScript. Real transformer inference needs
// either cgo and a native runtime or a network round trip, and both conflict
// with running inside the SMTP path by default.
type Embedder interface {
	// Name identifies the backend to scripts.
	Name() string
	// Dim is the dimensionality of the returned vectors.
	Dim() int
	// Embed returns the vector for a text.
	Embed(text string) ([]float32, error)
}

var embedders = map[string]Embedder{}

// RegisterEmbedder makes an embedding backend available to rule scripts.
func RegisterEmbedder(e Embedder) {
	if e == nil || e.Name() == "" {
		return
	}
	embedders[e.Name()] = e
}

// GetEmbedder returns a registered backend.
func GetEmbedder(name string) (Embedder, bool) {
	e, ok := embedders[name]
	return e, ok
}

// EmbedderNames lists the registered backends.
func EmbedderNames() []string {
	names := make([]string, 0, len(embedders))
	for name := range embedders {
		names = append(names, name)
	}
	return names
}

// DenseCosine returns the cosine similarity of two dense vectors, or zero if
// their lengths differ or either is all zeros.
func DenseCosine(a, b []float32) float64 {
	if len(a) != len(b) || len(a) == 0 {
		return 0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}

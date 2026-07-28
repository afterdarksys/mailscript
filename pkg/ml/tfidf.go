package ml

import (
	"hash/fnv"
	"math"
	"sort"
)

// SparseVector is a document represented as (feature index, weight) pairs,
// with indices in ascending order. Mail documents touch a tiny fraction of
// the vocabulary, so a dense vector would be almost entirely zeros.
type SparseVector struct {
	Indices []int     `json:"i"`
	Values  []float64 `json:"v"`
}

// Len returns the number of non-zero features.
func (s SparseVector) Len() int { return len(s.Indices) }

// Get returns the weight at a feature index, or zero.
func (s SparseVector) Get(index int) float64 {
	lo := sort.SearchInts(s.Indices, index)
	if lo < len(s.Indices) && s.Indices[lo] == index {
		return s.Values[lo]
	}
	return 0
}

// Dot returns the inner product with a dense weight vector.
func (s SparseVector) Dot(dense []float64) float64 {
	sum := 0.0
	for k, idx := range s.Indices {
		if idx < len(dense) {
			sum += s.Values[k] * dense[idx]
		}
	}
	return sum
}

// Norm returns the L2 norm.
func (s SparseVector) Norm() float64 {
	sum := 0.0
	for _, v := range s.Values {
		sum += v * v
	}
	return math.Sqrt(sum)
}

// CosineSimilarity returns the cosine of the angle between two vectors, in
// the range -1 to 1. Two documents with no shared features score 0.
func CosineSimilarity(a, b SparseVector) float64 {
	na, nb := a.Norm(), b.Norm()
	if na == 0 || nb == 0 {
		return 0
	}

	dot := 0.0
	i, j := 0, 0
	for i < len(a.Indices) && j < len(b.Indices) {
		switch {
		case a.Indices[i] == b.Indices[j]:
			dot += a.Values[i] * b.Values[j]
			i++
			j++
		case a.Indices[i] < b.Indices[j]:
			i++
		default:
			j++
		}
	}
	return dot / (na * nb)
}

// Vectorizer converts documents to TF-IDF weighted sparse vectors.
//
// Two vocabulary strategies are supported. The default builds an explicit
// term-to-index map during Fit, which keeps features interpretable. Setting
// HashDim switches to the hashing trick, which needs no Fit pass and bounds
// memory regardless of corpus size, at the cost of collisions and
// interpretability.
type Vectorizer struct {
	Analyzer *Analyzer `json:"analyzer"`

	// Vocab maps a term to its feature index. Empty when hashing.
	Vocab map[string]int `json:"vocab,omitempty"`
	// IDF holds the inverse document frequency per feature index.
	IDF []float64 `json:"idf,omitempty"`
	// NDocs is the number of documents seen during Fit.
	NDocs int `json:"n_docs"`

	// MinDF drops terms appearing in fewer than this many documents.
	MinDF int `json:"min_df"`
	// MaxDFRatio drops terms appearing in more than this fraction of
	// documents; such terms carry no discriminative signal.
	MaxDFRatio float64 `json:"max_df_ratio"`
	// MaxFeatures caps the vocabulary to the most frequent terms. 0 means no
	// cap.
	MaxFeatures int `json:"max_features"`

	// HashDim, when non-zero, selects the hashing trick with this many
	// buckets instead of a learned vocabulary.
	HashDim int `json:"hash_dim,omitempty"`

	// Sublinear applies 1+log(tf) instead of raw term frequency, which stops
	// a word repeated fifty times from dominating the vector.
	Sublinear bool `json:"sublinear"`
	// L2Normalize scales each vector to unit length so that document length
	// does not affect the score.
	L2Normalize bool `json:"l2_normalize"`
}

// NewVectorizer returns a vectorizer with defaults suited to email.
func NewVectorizer() *Vectorizer {
	return &Vectorizer{
		Analyzer:    DefaultAnalyzer(),
		MinDF:       2,
		MaxDFRatio:  0.95,
		MaxFeatures: 50000,
		Sublinear:   true,
		L2Normalize: true,
	}
}

// NewHashingVectorizer returns a vectorizer that needs no fitting pass.
func NewHashingVectorizer(dim int) *Vectorizer {
	if dim <= 0 {
		dim = 1 << 18
	}
	return &Vectorizer{
		Analyzer:    DefaultAnalyzer(),
		HashDim:     dim,
		Sublinear:   true,
		L2Normalize: true,
	}
}

// NumFeatures returns the dimensionality of the output vectors.
func (v *Vectorizer) NumFeatures() int {
	if v.HashDim > 0 {
		return v.HashDim
	}
	return len(v.Vocab)
}

// Fit learns the vocabulary and IDF weights from a corpus. It is a no-op for
// a hashing vectorizer, which has no state to learn.
func (v *Vectorizer) Fit(docs []string) {
	if v.HashDim > 0 {
		v.NDocs = len(docs)
		return
	}
	if v.Analyzer == nil {
		v.Analyzer = DefaultAnalyzer()
	}

	docFreq := make(map[string]int)
	for _, doc := range docs {
		seen := make(map[string]bool)
		for _, token := range v.Analyzer.Analyze(doc) {
			if seen[token] {
				continue
			}
			seen[token] = true
			docFreq[token]++
		}
	}

	v.NDocs = len(docs)
	maxDF := v.NDocs
	if v.MaxDFRatio > 0 && v.MaxDFRatio < 1 {
		maxDF = int(v.MaxDFRatio * float64(v.NDocs))
		if maxDF < 1 {
			maxDF = 1
		}
	}

	type termDF struct {
		term string
		df   int
	}
	kept := make([]termDF, 0, len(docFreq))
	for term, df := range docFreq {
		if v.MinDF > 0 && df < v.MinDF {
			continue
		}
		if df > maxDF {
			continue
		}
		kept = append(kept, termDF{term, df})
	}

	// Sort by descending frequency, then by term so the vocabulary is
	// deterministic across runs and models are reproducible.
	sort.Slice(kept, func(i, j int) bool {
		if kept[i].df != kept[j].df {
			return kept[i].df > kept[j].df
		}
		return kept[i].term < kept[j].term
	})
	if v.MaxFeatures > 0 && len(kept) > v.MaxFeatures {
		kept = kept[:v.MaxFeatures]
	}

	// Index terms in lexical order so the feature space is stable.
	sort.Slice(kept, func(i, j int) bool { return kept[i].term < kept[j].term })

	v.Vocab = make(map[string]int, len(kept))
	v.IDF = make([]float64, len(kept))
	for i, entry := range kept {
		v.Vocab[entry.term] = i
		// Smoothed IDF, as in scikit-learn: adding one to both the document
		// count and the document frequency keeps the weight finite for a term
		// present in every document.
		v.IDF[i] = math.Log(float64(1+v.NDocs)/float64(1+entry.df)) + 1
	}
}

// Transform converts one document to a TF-IDF vector.
func (v *Vectorizer) Transform(doc string) SparseVector {
	if v.Analyzer == nil {
		v.Analyzer = DefaultAnalyzer()
	}
	return v.transformTokens(v.Analyzer.Analyze(doc))
}

// TransformTokens converts a pre-tokenised document.
func (v *Vectorizer) TransformTokens(tokens []string) SparseVector {
	return v.transformTokens(tokens)
}

func (v *Vectorizer) transformTokens(tokens []string) SparseVector {
	counts := make(map[int]float64)

	for _, token := range tokens {
		idx, ok := v.featureIndex(token)
		if !ok {
			continue // out-of-vocabulary term
		}
		counts[idx]++
	}
	if len(counts) == 0 {
		return SparseVector{}
	}

	indices := make([]int, 0, len(counts))
	for idx := range counts {
		indices = append(indices, idx)
	}
	sort.Ints(indices)

	values := make([]float64, len(indices))
	for k, idx := range indices {
		tf := counts[idx]
		if v.Sublinear {
			tf = 1 + math.Log(tf)
		}
		weight := tf
		if idx < len(v.IDF) {
			weight *= v.IDF[idx]
		}
		values[k] = weight
	}

	vec := SparseVector{Indices: indices, Values: values}
	if v.L2Normalize {
		if norm := vec.Norm(); norm > 0 {
			for i := range vec.Values {
				vec.Values[i] /= norm
			}
		}
	}
	return vec
}

// featureIndex maps a term to its column, either through the learned
// vocabulary or the hash function.
func (v *Vectorizer) featureIndex(term string) (int, bool) {
	if v.HashDim > 0 {
		h := fnv.New32a()
		_, _ = h.Write([]byte(term))
		return int(h.Sum32() % uint32(v.HashDim)), true
	}
	idx, ok := v.Vocab[term]
	return idx, ok
}

// FeatureNames returns the vocabulary in index order. It is empty for a
// hashing vectorizer, whose features are not invertible.
func (v *Vectorizer) FeatureNames() []string {
	if v.HashDim > 0 || len(v.Vocab) == 0 {
		return nil
	}
	names := make([]string, len(v.Vocab))
	for term, idx := range v.Vocab {
		if idx < len(names) {
			names[idx] = term
		}
	}
	return names
}

// TopFeatures returns the n highest-weighted terms of a vector, most
// significant first. It returns nil for a hashing vectorizer.
func (v *Vectorizer) TopFeatures(vec SparseVector, n int) []FeatureWeight {
	names := v.FeatureNames()
	if names == nil {
		return nil
	}

	pairs := make([]FeatureWeight, 0, vec.Len())
	for k, idx := range vec.Indices {
		if idx < len(names) {
			pairs = append(pairs, FeatureWeight{Term: names[idx], Weight: vec.Values[k]})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].Weight != pairs[j].Weight {
			return pairs[i].Weight > pairs[j].Weight
		}
		return pairs[i].Term < pairs[j].Term
	})
	if n > 0 && len(pairs) > n {
		pairs = pairs[:n]
	}
	return pairs
}

// FeatureWeight pairs a term with its weight in a document.
type FeatureWeight struct {
	Term   string  `json:"term"`
	Weight float64 `json:"weight"`
}

package ml

import (
	"fmt"
	"math"
	"sort"
)

// TokenStore keeps raw token occurrence counts for the two-class Robinson
// and Fisher scorers. Counts[term][class] and ClassDocs[class] are persisted.
type TokenStore struct {
	Counts           map[string][2]int `json:"counts"`
	ClassDocs        [2]int            `json:"class_docs"`
	Classes          [2]string         `json:"classes"`
	PriorStrength    float64           `json:"prior_strength"`
	PriorProbability float64           `json:"prior_probability"`
	MaxInteresting   int               `json:"max_interesting"`
}

type tokenEvidence struct {
	term string
	p    float64
	dist float64
}

func NewTokenStore(classes []string) (*TokenStore, error) {
	if len(classes) != 2 {
		return nil, fmt.Errorf("ml: Robinson/Fisher scorers require exactly two classes")
	}
	return &TokenStore{Counts: map[string][2]int{}, ClassDocs: [2]int{}, Classes: [2]string{classes[0], classes[1]}, PriorStrength: 0.45, PriorProbability: 0.5, MaxInteresting: 150}, nil
}

func (s *TokenStore) Fit(docs []LabeledDoc, analyzer *Analyzer) error {
	if s == nil {
		return ErrNotTrained
	}
	index := map[string]int{s.Classes[0]: 0, s.Classes[1]: 1}
	for _, doc := range docs {
		class, ok := index[doc.Label]
		if !ok {
			return fmt.Errorf("ml: unknown token-store class %q", doc.Label)
		}
		s.ClassDocs[class]++
		for token, count := range TokenCounts(analyzer.Analyze(doc.Text)) {
			counts := s.Counts[token]
			counts[class] += count
			s.Counts[token] = counts
		}
	}
	return nil
}

func (s *TokenStore) evidence(text string, analyzer *Analyzer) []tokenEvidence {
	seen := map[string]bool{}
	var out []tokenEvidence
	for _, token := range analyzer.Analyze(text) {
		if seen[token] {
			continue
		}
		seen[token] = true
		counts, ok := s.Counts[token]
		if !ok {
			continue
		}
		goodDocs, badDocs := float64(maxInt(s.ClassDocs[0], 1)), float64(maxInt(s.ClassDocs[1], 1))
		goodRate, badRate := float64(counts[0])/goodDocs, float64(counts[1])/badDocs
		if goodRate+badRate == 0 {
			continue
		}
		raw := badRate / (badRate + goodRate)
		n := float64(counts[0] + counts[1])
		strength, prior := s.PriorStrength, s.PriorProbability
		if strength <= 0 {
			strength = 0.45
		}
		if prior <= 0 || prior >= 1 {
			prior = 0.5
		}
		p := (strength*prior + n*raw) / (strength + n)
		out = append(out, tokenEvidence{term: token, p: p, dist: math.Abs(p - 0.5)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].dist > out[j].dist })
	limit := s.MaxInteresting
	if limit <= 0 {
		limit = 150
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func (s *TokenStore) Score(text, scorer string, analyzer *Analyzer) (float64, bool) {
	evidence := s.evidence(text, analyzer)
	if len(evidence) == 0 {
		return 0.5, true
	}
	var logP, logQ float64
	for _, item := range evidence {
		logP += safeLog(1 - item.p)
		logQ += safeLog(item.p)
	}
	n := float64(len(evidence))
	var score float64
	if scorer == "robinson" {
		p := 1 - math.Exp(logP/n)
		q := 1 - math.Exp(logQ/n)
		if p+q == 0 {
			score = 0.5
		} else {
			score = ((p-q)/(p+q) + 1) / 2
		}
	} else {
		h := ChiSquareP(-2*logQ, 2*len(evidence))
		spam := ChiSquareP(-2*logP, 2*len(evidence))
		score = (1 + h - spam) / 2
	}
	if score < 0 {
		score = 0
	}
	if score > 1 {
		score = 1
	}
	return score, score >= 0.4 && score <= 0.6
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

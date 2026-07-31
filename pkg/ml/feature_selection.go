package ml

import (
	"math"
	"sort"
)

// selectChiSquareFeatures keeps terms whose document presence is least
// independent of class label (Pearson chi-square), then rebuilds the fitted
// vocabulary in stable lexical order.
func selectChiSquareFeatures(v *Vectorizer, docs []LabeledDoc, classes []string, limit int) {
	if v == nil || v.HashDim > 0 || limit <= 0 || len(v.Vocab) <= limit {
		return
	}
	classIndex := map[string]int{}
	for i, class := range classes {
		classIndex[class] = i
	}
	classDocs := make([]int, len(classes))
	present := map[string][]int{}
	for _, doc := range docs {
		ci, ok := classIndex[doc.Label]
		if !ok {
			continue
		}
		classDocs[ci]++
		seen := map[string]bool{}
		for _, term := range v.Analyzer.Analyze(doc.Text) {
			if seen[term] {
				continue
			}
			seen[term] = true
			if _, ok := v.Vocab[term]; !ok {
				continue
			}
			if present[term] == nil {
				present[term] = make([]int, len(classes))
			}
			present[term][ci]++
		}
	}
	type scored struct {
		term  string
		score float64
		old   int
	}
	items := make([]scored, 0, len(v.Vocab))
	total := len(docs)
	for term, old := range v.Vocab {
		row := present[term]
		with := 0
		for _, n := range row {
			with += n
		}
		without := total - with
		score := 0.0
		for ci, classTotal := range classDocs {
			for _, cell := range [][2]int{{row[ci], with}, {classTotal - row[ci], without}} {
				expected := float64(cell[1]*classTotal) / float64(maxInt(total, 1))
				if expected > 0 {
					delta := float64(cell[0]) - expected
					score += delta * delta / expected
				}
			}
		}
		if math.IsNaN(score) {
			score = 0
		}
		items = append(items, scored{term, score, old})
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score > items[j].score
		}
		return items[i].term < items[j].term
	})
	items = items[:limit]
	sort.Slice(items, func(i, j int) bool { return items[i].term < items[j].term })
	oldIDF := v.IDF
	v.Vocab = make(map[string]int, len(items))
	v.IDF = make([]float64, len(items))
	for i, item := range items {
		v.Vocab[item.term] = i
		if item.old < len(oldIDF) {
			v.IDF[i] = oldIDF[item.old]
		}
	}
}

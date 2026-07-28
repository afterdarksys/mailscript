//go:build golearn

// This file is compiled only with -tags golearn. It adds GoLearn's algorithm
// catalogue (kNN, decision trees, random forests) on top
// of the same TF-IDF feature space the native classifier uses, so a model
// trained either way consumes identical features.
//
// GoLearn's learners operate on dense matrices. A full email vocabulary of
// fifty thousand terms would allocate a dense row per document and exhaust
// memory on any real corpus, so the feature space is reduced hard before
// handing it over. That reduction is why the native multinomial Naive Bayes
// remains the default: it consumes the sparse vectors directly.

package ml

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/sjwhitworth/golearn/base"
	"github.com/sjwhitworth/golearn/ensemble"
	"github.com/sjwhitworth/golearn/evaluation"
	"github.com/sjwhitworth/golearn/knn"
	"github.com/sjwhitworth/golearn/trees"
)

// ErrGoLearnDisabled is never returned from this build; it exists so callers
// can reference it unconditionally.
var ErrGoLearnDisabled = errors.New("ml: GoLearn support is compiled in")

// GoLearnAvailable reports whether GoLearn-backed algorithms are compiled in.
func GoLearnAvailable() bool { return true }

// GoLearnAlgorithms lists the algorithms this build can train.
//
// Logistic regression is absent deliberately: GoLearn's implementation is a
// cgo binding around liblinear and does not satisfy the base.Classifier
// interface the rest of the library uses, so it cannot be driven through the
// same code path. The native Naive Bayes classifier covers the same ground
// without cgo.
func GoLearnAlgorithms() []string {
	return []string{"knn", "tree", "randomforest"}
}

// GoLearnOptions configures a GoLearn-backed training run.
type GoLearnOptions struct {
	Algorithm    string
	K            int
	TreeCount    int
	MaxFeatures  int
	Vectorizer   *Vectorizer
	HoldoutRatio float64
	Seed         int64
}

// defaultGoLearnFeatures bounds the dense matrix GoLearn allocates. At this
// width a ten-thousand-document corpus needs roughly 160 MB of float64,
// which is the most that is reasonable to ask of a mail gateway host.
const defaultGoLearnFeatures = 2000

// GoLearnModel wraps a trained GoLearn classifier and the vectorizer that
// produced its features.
type GoLearnModel struct {
	Algorithm  string       `json:"algorithm"`
	Classes    []string     `json:"classes"`
	Vectorizer *Vectorizer  `json:"vectorizer"`
	Metrics    *EvalMetrics `json:"metrics,omitempty"`

	// featureIdx maps a vectorizer column to a dense matrix column, since the
	// dense space is a reduced subset of the full vocabulary.
	featureIdx map[int]int
	// order lists vectorizer columns in dense-column order.
	order []int

	classifier base.Classifier
	template   base.FixedDataGrid
}

// TrainGoLearn fits a GoLearn classifier over TF-IDF features.
func TrainGoLearn(docs []LabeledDoc, opts GoLearnOptions) (*GoLearnModel, error) {
	if len(docs) < 2 {
		return nil, errors.New("ml: need at least two training documents")
	}
	if opts.Algorithm == "" {
		opts.Algorithm = "knn"
	}
	if opts.MaxFeatures <= 0 {
		opts.MaxFeatures = defaultGoLearnFeatures
	}
	if opts.K <= 0 {
		opts.K = 5
	}
	if opts.TreeCount <= 0 {
		opts.TreeCount = 20
	}

	classSet := map[string]bool{}
	for _, d := range docs {
		classSet[d.Label] = true
	}
	if len(classSet) < 2 {
		return nil, fmt.Errorf("ml: corpus has only %d class; at least two are required", len(classSet))
	}
	classes := make([]string, 0, len(classSet))
	for c := range classSet {
		classes = append(classes, c)
	}
	sort.Strings(classes)

	train, holdout := splitCorpus(docs, opts.HoldoutRatio, opts.Seed)
	if len(train) == 0 {
		train, holdout = docs, nil
	}

	vec := opts.Vectorizer
	if vec == nil {
		vec = NewVectorizer()
		vec.MaxFeatures = opts.MaxFeatures
		corpus := make([]string, len(train))
		for i, d := range train {
			corpus[i] = d.Text
		}
		vec.Fit(corpus)
	}
	if vec.NumFeatures() == 0 {
		return nil, errors.New("ml: vocabulary is empty after filtering")
	}

	model := &GoLearnModel{
		Algorithm:  opts.Algorithm,
		Classes:    classes,
		Vectorizer: vec,
	}

	vectors := make([]SparseVector, len(train))
	for i, d := range train {
		vectors[i] = vec.Transform(d.Text)
	}
	model.selectFeatures(vectors, opts.MaxFeatures)

	instances, err := model.buildInstances(vectors, train)
	if err != nil {
		return nil, err
	}
	model.template = instances

	switch strings.ToLower(opts.Algorithm) {
	case "knn":
		model.classifier = knn.NewKnnClassifier("euclidean", "linear", opts.K)
	case "tree":
		model.classifier = trees.NewID3DecisionTree(0.6)
	case "randomforest":
		attrsPerTree := int(float64(len(model.order))/3) + 1
		model.classifier = ensemble.NewRandomForest(opts.TreeCount, attrsPerTree)
	default:
		return nil, fmt.Errorf("ml: unknown GoLearn algorithm %q (have %s)",
			opts.Algorithm, strings.Join(GoLearnAlgorithms(), ", "))
	}

	if err := model.classifier.Fit(instances); err != nil {
		return nil, fmt.Errorf("ml: fit %s: %w", opts.Algorithm, err)
	}

	if len(holdout) > 0 {
		metrics := model.evaluate(holdout)
		model.Metrics = &metrics
	}

	return model, nil
}

// selectFeatures picks the highest-mass columns to form the dense space.
// Ranking by summed TF-IDF weight keeps the terms that carry the most signal
// across the corpus rather than merely the most frequent ones.
func (m *GoLearnModel) selectFeatures(vectors []SparseVector, limit int) {
	mass := map[int]float64{}
	for _, vec := range vectors {
		for k, idx := range vec.Indices {
			mass[idx] += vec.Values[k]
		}
	}

	cols := make([]int, 0, len(mass))
	for idx := range mass {
		cols = append(cols, idx)
	}
	sort.Slice(cols, func(i, j int) bool {
		if mass[cols[i]] != mass[cols[j]] {
			return mass[cols[i]] > mass[cols[j]]
		}
		return cols[i] < cols[j]
	})
	if limit > 0 && len(cols) > limit {
		cols = cols[:limit]
	}
	sort.Ints(cols)

	m.order = cols
	m.featureIdx = make(map[int]int, len(cols))
	for dense, sparse := range cols {
		m.featureIdx[sparse] = dense
	}
}

// buildInstances converts sparse vectors into the dense grid GoLearn needs.
func (m *GoLearnModel) buildInstances(vectors []SparseVector, docs []LabeledDoc) (base.FixedDataGrid, error) {
	if len(m.order) == 0 {
		return nil, errors.New("ml: no features selected for the dense matrix")
	}

	attrs := make([]base.Attribute, 0, len(m.order)+1)
	names := m.Vectorizer.FeatureNames()
	for _, sparseIdx := range m.order {
		name := fmt.Sprintf("f%d", sparseIdx)
		if sparseIdx < len(names) && names[sparseIdx] != "" {
			name = names[sparseIdx]
		}
		attrs = append(attrs, base.NewFloatAttribute(name))
	}

	classAttr := new(base.CategoricalAttribute)
	classAttr.SetName("class")
	for _, c := range m.Classes {
		classAttr.GetSysValFromString(c)
	}
	attrs = append(attrs, classAttr)

	instances := base.NewDenseInstances()
	specs := make([]base.AttributeSpec, len(attrs))
	for i, attr := range attrs {
		specs[i] = instances.AddAttribute(attr)
	}
	if err := instances.AddClassAttribute(attrs[len(attrs)-1]); err != nil {
		return nil, fmt.Errorf("ml: set class attribute: %w", err)
	}
	instances.Extend(len(vectors))

	for row, vec := range vectors {
		dense := make([]float64, len(m.order))
		for k, sparseIdx := range vec.Indices {
			if denseIdx, ok := m.featureIdx[sparseIdx]; ok {
				dense[denseIdx] = vec.Values[k]
			}
		}
		for col, value := range dense {
			instances.Set(specs[col], row, specs[col].GetAttribute().GetSysValFromString(
				fmt.Sprintf("%g", value)))
		}
		label := ""
		if row < len(docs) {
			label = docs[row].Label
		}
		instances.Set(specs[len(specs)-1], row,
			specs[len(specs)-1].GetAttribute().GetSysValFromString(label))
	}

	return instances, nil
}

// Classify scores a document with the trained GoLearn classifier.
func (m *GoLearnModel) Classify(text string) (Prediction, error) {
	if m == nil || m.classifier == nil {
		return Prediction{}, errors.New("ml: GoLearn model is not trained")
	}

	vec := m.Vectorizer.Transform(text)
	instances, err := m.buildInstances([]SparseVector{vec}, []LabeledDoc{{Label: m.Classes[0]}})
	if err != nil {
		return Prediction{}, err
	}

	predictions, err := m.classifier.Predict(instances)
	if err != nil {
		return Prediction{}, fmt.Errorf("ml: predict: %w", err)
	}

	label := ""
	for _, attr := range predictions.AllClassAttributes() {
		spec, serr := predictions.GetAttribute(attr)
		if serr != nil {
			continue
		}
		// Get returns the raw system value; the attribute knows how to render
		// it back to the class name.
		label = attr.GetStringFromSysVal(predictions.Get(spec, 0))
		break
	}
	label = strings.TrimSpace(label)

	// GoLearn's classifiers do not all expose calibrated probabilities, so
	// report a hard decision rather than inventing a confidence value.
	dist := make(map[string]float64, len(m.Classes))
	for _, c := range m.Classes {
		if c == label {
			dist[c] = 1
		} else {
			dist[c] = 0
		}
	}

	return Prediction{Label: label, Confidence: 1, Probabilities: dist}, nil
}

func (m *GoLearnModel) evaluate(docs []LabeledDoc) EvalMetrics {
	metrics := EvalMetrics{
		Samples:   len(docs),
		PerClass:  make(map[string]ClassMetrics, len(m.Classes)),
		Confusion: make(map[string]map[string]int, len(m.Classes)),
	}
	for _, actual := range m.Classes {
		metrics.Confusion[actual] = make(map[string]int, len(m.Classes))
	}

	correct := 0
	truePos, falsePos, falseNeg, support := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}

	for _, d := range docs {
		pred, err := m.Classify(d.Text)
		if err != nil {
			continue
		}
		support[d.Label]++
		metrics.Confusion[d.Label][pred.Label]++
		if pred.Label == d.Label {
			correct++
			truePos[d.Label]++
		} else {
			falsePos[pred.Label]++
			falseNeg[d.Label]++
		}
	}

	if len(docs) > 0 {
		metrics.Accuracy = float64(correct) / float64(len(docs))
	}
	for _, class := range m.Classes {
		tp, fp, fn := truePos[class], falsePos[class], falseNeg[class]
		cm := ClassMetrics{Support: support[class]}
		if tp+fp > 0 {
			cm.Precision = float64(tp) / float64(tp+fp)
		}
		if tp+fn > 0 {
			cm.Recall = float64(tp) / float64(tp+fn)
		}
		if cm.Precision+cm.Recall > 0 {
			cm.F1 = 2 * cm.Precision * cm.Recall / (cm.Precision + cm.Recall)
		}
		metrics.PerClass[class] = cm
	}

	return metrics
}

// Save persists the vectorizer and metadata. The fitted GoLearn classifier
// itself is not serialised: GoLearn has no stable cross-version model format,
// so a saved artefact records what to retrain rather than pretending to
// round-trip the learner.
func (m *GoLearnModel) Save(path string) error {
	payload := struct {
		Algorithm  string       `json:"algorithm"`
		Classes    []string     `json:"classes"`
		Vectorizer *Vectorizer  `json:"vectorizer"`
		Metrics    *EvalMetrics `json:"metrics,omitempty"`
		Note       string       `json:"note"`
	}{
		Algorithm:  m.Algorithm,
		Classes:    m.Classes,
		Vectorizer: m.Vectorizer,
		Metrics:    m.Metrics,
		Note:       "GoLearn classifiers are not serialisable; retrain from the corpus using this vectorizer",
	}

	data, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return fmt.Errorf("ml: encode GoLearn model: %w", err)
	}
	return os.WriteFile(path, data, 0o644)
}

// CrossValidate reports GoLearn's own evaluation summary for a fitted model.
func (m *GoLearnModel) CrossValidate() (string, error) {
	if m == nil || m.classifier == nil || m.template == nil {
		return "", errors.New("ml: GoLearn model is not trained")
	}
	predictions, err := m.classifier.Predict(m.template)
	if err != nil {
		return "", err
	}
	matrix, err := evaluation.GetConfusionMatrix(m.template, predictions)
	if err != nil {
		return "", err
	}
	return evaluation.GetSummary(matrix), nil
}

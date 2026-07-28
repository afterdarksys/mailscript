package ml

import (
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// ModelFormatVersion is incremented when the serialised layout changes in a
// way older binaries cannot read.
const ModelFormatVersion = 1

// Model bundles a vectorizer and a classifier into the single artefact a rule
// script loads.
type Model struct {
	FormatVersion int      `json:"format_version"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	CreatedAt     string   `json:"created_at,omitempty"`
	Classes       []string `json:"classes"`

	Vectorizer *Vectorizer `json:"vectorizer"`
	Classifier *NaiveBayes `json:"classifier"`

	// Metrics records how the model scored on held-out data at training time.
	Metrics *EvalMetrics `json:"metrics,omitempty"`
}

// LabeledDoc is one training example.
type LabeledDoc struct {
	Label string
	Text  string
}

// TrainOptions configures a training run.
type TrainOptions struct {
	Name        string
	Description string
	Analyzer    *Analyzer
	Alpha       float64
	MinDF       int
	MaxDFRatio  float64
	MaxFeatures int
	HashDim     int
	// HoldoutRatio reserves this fraction of the corpus for evaluation.
	// Zero skips evaluation and trains on everything.
	HoldoutRatio float64
	// Seed makes the holdout split reproducible.
	Seed int64
}

// DefaultTrainOptions returns options suited to a spam or ham corpus.
func DefaultTrainOptions() TrainOptions {
	return TrainOptions{
		Name:         "mailscript-classifier",
		Alpha:        1.0,
		MinDF:        2,
		MaxDFRatio:   0.95,
		MaxFeatures:  50000,
		HoldoutRatio: 0.2,
		Seed:         42,
	}
}

// Train fits a vectorizer and classifier over a labelled corpus.
func Train(docs []LabeledDoc, opts TrainOptions) (*Model, error) {
	if len(docs) < 2 {
		return nil, errors.New("ml: need at least two training documents")
	}
	if opts.Alpha <= 0 {
		opts.Alpha = 1.0
	}

	classSet := map[string]bool{}
	for _, d := range docs {
		if strings.TrimSpace(d.Label) == "" {
			return nil, errors.New("ml: training document has an empty label")
		}
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

	classIndex := make(map[string]int, len(classes))
	for i, c := range classes {
		classIndex[c] = i
	}

	train, holdout := splitCorpus(docs, opts.HoldoutRatio, opts.Seed)
	if len(train) == 0 {
		train = docs
		holdout = nil
	}

	var vec *Vectorizer
	if opts.HashDim > 0 {
		vec = NewHashingVectorizer(opts.HashDim)
	} else {
		vec = NewVectorizer()
		vec.MinDF = opts.MinDF
		vec.MaxDFRatio = opts.MaxDFRatio
		vec.MaxFeatures = opts.MaxFeatures
	}
	if opts.Analyzer != nil {
		vec.Analyzer = opts.Analyzer
	}

	corpus := make([]string, len(train))
	for i, d := range train {
		corpus[i] = d.Text
	}
	vec.Fit(corpus)

	if vec.NumFeatures() == 0 {
		return nil, errors.New("ml: vocabulary is empty after filtering; lower min_df or supply more data")
	}

	X := make([]SparseVector, len(train))
	y := make([]int, len(train))
	for i, d := range train {
		X[i] = vec.Transform(d.Text)
		y[i] = classIndex[d.Label]
	}

	nb := &NaiveBayes{Alpha: opts.Alpha}
	if err := nb.Fit(X, y, classes, vec.NumFeatures()); err != nil {
		return nil, err
	}

	model := &Model{
		FormatVersion: ModelFormatVersion,
		Name:          opts.Name,
		Description:   opts.Description,
		Classes:       classes,
		Vectorizer:    vec,
		Classifier:    nb,
	}

	if len(holdout) > 0 {
		metrics := model.Evaluate(holdout)
		model.Metrics = &metrics
	}

	return model, nil
}

// splitCorpus deterministically partitions a corpus into training and
// holdout sets. A linear congruential shuffle keeps the split reproducible
// without pulling in math/rand's global state.
func splitCorpus(docs []LabeledDoc, ratio float64, seed int64) (train, holdout []LabeledDoc) {
	if ratio <= 0 || ratio >= 1 || len(docs) < 5 {
		return docs, nil
	}

	order := make([]int, len(docs))
	for i := range order {
		order[i] = i
	}

	state := uint64(seed)
	if state == 0 {
		state = 1
	}
	for i := len(order) - 1; i > 0; i-- {
		state = state*6364136223846793005 + 1442695040888963407
		j := int((state >> 33) % uint64(i+1))
		order[i], order[j] = order[j], order[i]
	}

	cut := int(float64(len(docs)) * (1 - ratio))
	if cut < 1 {
		cut = 1
	}
	if cut >= len(docs) {
		cut = len(docs) - 1
	}

	for _, idx := range order[:cut] {
		train = append(train, docs[idx])
	}
	for _, idx := range order[cut:] {
		holdout = append(holdout, docs[idx])
	}
	return train, holdout
}

// Classify scores a document.
func (m *Model) Classify(text string) (Prediction, error) {
	if m == nil || m.Vectorizer == nil || m.Classifier == nil {
		return Prediction{}, ErrNotTrained
	}
	return m.Classifier.Predict(m.Vectorizer.Transform(text))
}

// ScoreFor returns the probability that a document belongs to a named class.
func (m *Model) ScoreFor(text, class string) (float64, error) {
	if m == nil || m.Vectorizer == nil || m.Classifier == nil {
		return 0, ErrNotTrained
	}
	return m.Classifier.ProbabilityOf(m.Vectorizer.Transform(text), class)
}

// Explain returns the terms in a document that most influenced its
// classification toward the predicted class.
func (m *Model) Explain(text string, n int) ([]FeatureWeight, error) {
	if m == nil || m.Vectorizer == nil || m.Classifier == nil {
		return nil, ErrNotTrained
	}
	return m.Vectorizer.TopFeatures(m.Vectorizer.Transform(text), n), nil
}

// EvalMetrics summarises classifier performance on held-out data.
type EvalMetrics struct {
	Samples   int                       `json:"samples"`
	Accuracy  float64                   `json:"accuracy"`
	PerClass  map[string]ClassMetrics   `json:"per_class"`
	Confusion map[string]map[string]int `json:"confusion"`
}

// ClassMetrics holds per-class precision, recall and F1.
type ClassMetrics struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1        float64 `json:"f1"`
	Support   int     `json:"support"`
}

// Evaluate scores the model against labelled documents.
func (m *Model) Evaluate(docs []LabeledDoc) EvalMetrics {
	metrics := EvalMetrics{
		Samples:   len(docs),
		PerClass:  make(map[string]ClassMetrics, len(m.Classes)),
		Confusion: make(map[string]map[string]int, len(m.Classes)),
	}
	if len(docs) == 0 {
		return metrics
	}

	for _, actual := range m.Classes {
		metrics.Confusion[actual] = make(map[string]int, len(m.Classes))
		for _, predicted := range m.Classes {
			metrics.Confusion[actual][predicted] = 0
		}
	}

	correct := 0
	truePos := map[string]int{}
	falsePos := map[string]int{}
	falseNeg := map[string]int{}
	support := map[string]int{}

	for _, d := range docs {
		pred, err := m.Classify(d.Text)
		if err != nil {
			continue
		}
		support[d.Label]++
		if _, ok := metrics.Confusion[d.Label]; ok {
			metrics.Confusion[d.Label][pred.Label]++
		}
		if pred.Label == d.Label {
			correct++
			truePos[d.Label]++
		} else {
			falsePos[pred.Label]++
			falseNeg[d.Label]++
		}
	}

	metrics.Accuracy = float64(correct) / float64(len(docs))

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

// Save writes the model to a file. A ".gz" suffix selects gzip compression,
// which matters because a fitted vocabulary of fifty thousand terms
// serialises to several megabytes of JSON.
func (m *Model) Save(path string) error {
	if m == nil {
		return errors.New("ml: cannot save a nil model")
	}
	m.FormatVersion = ModelFormatVersion

	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("ml: create model directory: %w", err)
		}
	}

	file, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("ml: create model file: %w", err)
	}
	defer file.Close()

	var w io.Writer = file
	if strings.HasSuffix(path, ".gz") {
		gz := gzip.NewWriter(file)
		defer gz.Close()
		w = gz
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(m); err != nil {
		return fmt.Errorf("ml: encode model: %w", err)
	}
	return nil
}

// LoadModel reads a model from disk, transparently handling gzip.
func LoadModel(path string) (*Model, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("ml: open model: %w", err)
	}
	defer file.Close()

	var r io.Reader = file
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("ml: open gzip model: %w", err)
		}
		defer gz.Close()
		r = gz
	}

	var model Model
	if err := json.NewDecoder(r).Decode(&model); err != nil {
		return nil, fmt.Errorf("ml: decode model: %w", err)
	}

	if model.FormatVersion > ModelFormatVersion {
		return nil, fmt.Errorf("ml: model format version %d is newer than the supported version %d",
			model.FormatVersion, ModelFormatVersion)
	}
	if model.Vectorizer == nil || model.Classifier == nil {
		return nil, errors.New("ml: model file is missing its vectorizer or classifier")
	}
	if model.Vectorizer.Analyzer == nil {
		model.Vectorizer.Analyzer = DefaultAnalyzer()
	}

	return &model, nil
}

// Registry holds the models available to rule scripts, keyed by the name a
// script refers to them by.
type Registry struct {
	models map[string]*Model
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{models: make(map[string]*Model)}
}

// Add registers a model under a name.
func (r *Registry) Add(name string, model *Model) {
	if r.models == nil {
		r.models = make(map[string]*Model)
	}
	r.models[name] = model
}

// LoadFile loads a model from disk and registers it. When name is empty the
// model's own name is used, falling back to the file's base name.
func (r *Registry) LoadFile(name, path string) error {
	model, err := LoadModel(path)
	if err != nil {
		return err
	}
	if name == "" {
		name = model.Name
	}
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	r.Add(name, model)
	return nil
}

// Get returns a registered model.
func (r *Registry) Get(name string) (*Model, bool) {
	if r == nil || r.models == nil {
		return nil, false
	}
	model, ok := r.models[name]
	return model, ok
}

// Default returns the model registered as "default", or the only registered
// model when exactly one exists. Scripts that use a single model can then
// omit the name.
func (r *Registry) Default() (*Model, bool) {
	if r == nil || len(r.models) == 0 {
		return nil, false
	}
	if model, ok := r.models["default"]; ok {
		return model, true
	}
	if len(r.models) == 1 {
		for _, model := range r.models {
			return model, true
		}
	}
	return nil, false
}

// Names returns the registered model names in sorted order.
func (r *Registry) Names() []string {
	if r == nil {
		return nil
	}
	names := make([]string, 0, len(r.models))
	for name := range r.models {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

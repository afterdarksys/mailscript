//go:build !golearn

package ml

import "errors"

// ErrGoLearnDisabled is returned when a GoLearn-backed classifier is
// requested from a binary built without the "golearn" build tag.
var ErrGoLearnDisabled = errors.New(
	"ml: GoLearn support is not compiled in; rebuild with -tags golearn")

// GoLearnAvailable reports whether GoLearn-backed algorithms are compiled in.
func GoLearnAvailable() bool { return false }

// GoLearnAlgorithms lists the algorithms this build can train. It is empty
// without the build tag.
func GoLearnAlgorithms() []string { return nil }

// TrainGoLearn is the no-op stand-in used when GoLearn is not compiled in.
func TrainGoLearn(_ []LabeledDoc, _ GoLearnOptions) (*GoLearnModel, error) {
	return nil, ErrGoLearnDisabled
}

// GoLearnOptions configures a GoLearn-backed training run. The fields are
// declared in both builds so that callers compile either way.
type GoLearnOptions struct {
	// Algorithm selects the learner: "knn", "tree", "randomforest", or
	// "logistic".
	Algorithm string
	// K is the neighbour count for kNN.
	K int
	// TreeCount is the forest size for randomforest.
	TreeCount int
	// MaxFeatures caps the feature space handed to GoLearn. Dense-matrix
	// learners cannot absorb a full TF-IDF vocabulary, so this is applied
	// aggressively by default.
	MaxFeatures int
	// Vectorizer supplies the feature space. When nil a fresh one is fitted.
	Vectorizer *Vectorizer
	// HoldoutRatio reserves this fraction of the corpus for evaluation.
	HoldoutRatio float64
	// Seed makes the holdout split reproducible.
	Seed int64
}

// GoLearnModel is the handle returned by TrainGoLearn. In a build without the
// tag it exists only so signatures type-check and is never instantiated.
type GoLearnModel struct {
	Algorithm  string
	Classes    []string
	Vectorizer *Vectorizer
	Metrics    *EvalMetrics
}

// Classify is unavailable without the build tag.
func (m *GoLearnModel) Classify(_ string) (Prediction, error) {
	return Prediction{}, ErrGoLearnDisabled
}

// Save is unavailable without the build tag.
func (m *GoLearnModel) Save(_ string) error { return ErrGoLearnDisabled }

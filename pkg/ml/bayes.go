package ml

import (
	"errors"
	"math"
	"sort"
)

// NaiveBayes is a multinomial Naive Bayes classifier over TF-IDF features.
//
// Multinomial NB is the right default for mail: it trains in one pass, needs
// no hyperparameter search, handles the high-dimensional sparse feature space
// that text produces, and stays accurate with a few hundred labelled
// examples. Its independence assumption is wrong for language, but the
// resulting probability estimates are still well-ordered, which is all a
// threshold rule needs.
type NaiveBayes struct {
	Classes []string `json:"classes"`
	// Alpha is the additive smoothing parameter. It stops an unseen term in a
	// class from driving the posterior to zero.
	Alpha float64 `json:"alpha"`
	// ClassLogPrior[c] is log P(class c).
	ClassLogPrior []float64 `json:"class_log_prior"`
	// FeatureLogProb[c][f] is log P(feature f | class c).
	FeatureLogProb [][]float64 `json:"feature_log_prob"`
	// NFeatures is the dimensionality the model was trained at.
	NFeatures int `json:"n_features"`
	// ClassCounts records how many training documents each class had.
	ClassCounts []int `json:"class_counts"`
}

// ErrNotTrained is returned when a classifier is used before fitting.
var ErrNotTrained = errors.New("ml: classifier has not been trained")

// NewNaiveBayes returns an untrained classifier with default smoothing.
func NewNaiveBayes() *NaiveBayes {
	return &NaiveBayes{Alpha: 1.0}
}

// Fit trains the classifier. X and y must be the same length; y holds indices
// into classes.
func (nb *NaiveBayes) Fit(X []SparseVector, y []int, classes []string, nFeatures int) error {
	if len(X) != len(y) {
		return errors.New("ml: feature and label counts differ")
	}
	if len(X) == 0 {
		return errors.New("ml: no training documents")
	}
	if len(classes) < 2 {
		return errors.New("ml: at least two classes are required")
	}
	if nFeatures <= 0 {
		return errors.New("ml: feature space is empty")
	}
	if nb.Alpha <= 0 {
		nb.Alpha = 1.0
	}

	nb.Classes = classes
	nb.NFeatures = nFeatures
	nb.ClassCounts = make([]int, len(classes))

	// featureSums[c][f] accumulates the weight of feature f across class c.
	featureSums := make([][]float64, len(classes))
	for c := range featureSums {
		featureSums[c] = make([]float64, nFeatures)
	}

	for i, vec := range X {
		label := y[i]
		if label < 0 || label >= len(classes) {
			return errors.New("ml: label index out of range")
		}
		nb.ClassCounts[label]++
		for k, idx := range vec.Indices {
			if idx < nFeatures {
				// TF-IDF weights are non-negative, but guard anyway: a
				// negative count would make the log undefined.
				if w := vec.Values[k]; w > 0 {
					featureSums[label][idx] += w
				}
			}
		}
	}

	nb.ClassLogPrior = make([]float64, len(classes))
	nb.FeatureLogProb = make([][]float64, len(classes))
	total := float64(len(X))

	for c := range classes {
		// A class with no examples would otherwise yield log(0).
		nb.ClassLogPrior[c] = math.Log((float64(nb.ClassCounts[c]) + nb.Alpha) /
			(total + nb.Alpha*float64(len(classes))))

		classTotal := 0.0
		for _, w := range featureSums[c] {
			classTotal += w
		}
		denominator := classTotal + nb.Alpha*float64(nFeatures)

		nb.FeatureLogProb[c] = make([]float64, nFeatures)
		for f := range featureSums[c] {
			nb.FeatureLogProb[c][f] = math.Log((featureSums[c][f] + nb.Alpha) / denominator)
		}
	}

	return nil
}

// jointLogLikelihood returns the unnormalised log posterior per class.
func (nb *NaiveBayes) jointLogLikelihood(x SparseVector) ([]float64, error) {
	if len(nb.Classes) == 0 || len(nb.FeatureLogProb) == 0 {
		return nil, ErrNotTrained
	}

	scores := make([]float64, len(nb.Classes))
	for c := range nb.Classes {
		score := nb.ClassLogPrior[c]
		probs := nb.FeatureLogProb[c]
		for k, idx := range x.Indices {
			if idx < len(probs) {
				score += x.Values[k] * probs[idx]
			}
		}
		scores[c] = score
	}
	return scores, nil
}

// PredictProba returns the posterior probability of each class, in the same
// order as Classes.
func (nb *NaiveBayes) PredictProba(x SparseVector) ([]float64, error) {
	scores, err := nb.jointLogLikelihood(x)
	if err != nil {
		return nil, err
	}

	// Softmax in log space. Subtracting the maximum before exponentiating
	// keeps the intermediate values from overflowing.
	max := scores[0]
	for _, s := range scores[1:] {
		if s > max {
			max = s
		}
	}

	sum := 0.0
	probs := make([]float64, len(scores))
	for i, s := range scores {
		probs[i] = math.Exp(s - max)
		sum += probs[i]
	}
	if sum == 0 {
		// Every class is equally (im)plausible; report a uniform posterior
		// rather than dividing by zero.
		uniform := 1 / float64(len(probs))
		for i := range probs {
			probs[i] = uniform
		}
		return probs, nil
	}
	for i := range probs {
		probs[i] /= sum
	}
	return probs, nil
}

// Prediction is a classification outcome.
type Prediction struct {
	Label         string             `json:"label"`
	Confidence    float64            `json:"confidence"`
	Probabilities map[string]float64 `json:"probabilities"`
}

// Predict returns the most probable class and the full distribution.
func (nb *NaiveBayes) Predict(x SparseVector) (Prediction, error) {
	probs, err := nb.PredictProba(x)
	if err != nil {
		return Prediction{}, err
	}

	best := 0
	for i, p := range probs {
		if p > probs[best] {
			best = i
		}
	}

	dist := make(map[string]float64, len(probs))
	for i, label := range nb.Classes {
		dist[label] = probs[i]
	}

	return Prediction{
		Label:         nb.Classes[best],
		Confidence:    probs[best],
		Probabilities: dist,
	}, nil
}

// ProbabilityOf returns the posterior for one named class, or zero when the
// class is unknown to the model.
func (nb *NaiveBayes) ProbabilityOf(x SparseVector, class string) (float64, error) {
	probs, err := nb.PredictProba(x)
	if err != nil {
		return 0, err
	}
	for i, label := range nb.Classes {
		if label == class {
			return probs[i], nil
		}
	}
	return 0, nil
}

// TopIndicators returns the features that most strongly favour a class over
// the average of the others, which is what makes a classification
// explainable to an operator reviewing a quarantine decision.
func (nb *NaiveBayes) TopIndicators(class string, names []string, n int) []FeatureWeight {
	target := -1
	for i, label := range nb.Classes {
		if label == class {
			target = i
			break
		}
	}
	if target < 0 || len(nb.FeatureLogProb) == 0 {
		return nil
	}

	pairs := make([]FeatureWeight, 0, nb.NFeatures)
	for f := 0; f < nb.NFeatures; f++ {
		other := 0.0
		count := 0
		for c := range nb.Classes {
			if c == target {
				continue
			}
			other += nb.FeatureLogProb[c][f]
			count++
		}
		if count == 0 {
			continue
		}
		delta := nb.FeatureLogProb[target][f] - other/float64(count)

		term := ""
		if f < len(names) {
			term = names[f]
		}
		pairs = append(pairs, FeatureWeight{Term: term, Weight: delta})
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

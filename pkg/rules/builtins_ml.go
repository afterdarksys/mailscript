package rules

import (
	"fmt"
	"sort"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/ml"
	"go.starlark.net/starlark"
)

// classifierText is the document a model sees for a message. The subject is
// included because it carries disproportionate signal for its length, and it
// is prefixed so that a term in the subject is a distinct feature from the
// same term in the body.
func (e *scriptEnv) classifierText() string {
	msg := e.msg
	var sb strings.Builder

	if subject := msg.Get("Subject"); subject != "" {
		sb.WriteString("subject: ")
		sb.WriteString(subject)
		sb.WriteString("\n")
	}
	if from := msg.Get("From"); from != "" {
		sb.WriteString("from: ")
		sb.WriteString(from)
		sb.WriteString("\n")
	}
	sb.WriteString(msg.SearchText())

	return sb.String()
}

// resolveModel returns the named model, or the registry default when the name
// is empty.
func (e *scriptEnv) resolveModel(name string) (*ml.Model, error) {
	registry := e.opts.Models
	if registry == nil {
		return nil, fmt.Errorf("no classification models are loaded; start with --model to load one")
	}
	if name == "" {
		model, ok := registry.Default()
		if !ok {
			return nil, fmt.Errorf("no default model; name one of: %s",
				strings.Join(registry.Names(), ", "))
		}
		return model, nil
	}
	model, ok := registry.Get(name)
	if !ok {
		return nil, fmt.Errorf("unknown model %q; loaded models: %s",
			name, strings.Join(registry.Names(), ", "))
	}
	return model, nil
}

func (e *scriptEnv) mlBuiltins() starlark.StringDict {
	msg := e.msg

	return starlark.StringDict{
		"ml_available": nullaryBool("ml_available", func() bool {
			if e.opts.Models == nil {
				return false
			}
			return len(e.opts.Models.Names()) > 0
		}),

		"ml_models": nullaryList("ml_models", func() []string {
			if e.opts.Models == nil {
				return nil
			}
			return e.opts.Models.Names()
		}),

		"golearn_available": nullaryBool("golearn_available", ml.GoLearnAvailable),

		"ml_scorer": starlark.NewBuiltin("ml_scorer",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var modelName string
				if err := starlark.UnpackArgs("ml_scorer", args, kwargs, "model?", &modelName); err != nil {
					return nil, err
				}
				model, err := e.resolveModel(modelName)
				if err != nil {
					return nil, fmt.Errorf("ml_scorer: %w", err)
				}
				return starlark.String(model.ScorerName()), nil
			}),

		"ml_unsure": starlark.NewBuiltin("ml_unsure",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var modelName, text string
				if err := starlark.UnpackArgs("ml_unsure", args, kwargs, "model?", &modelName, "text?", &text); err != nil {
					return nil, err
				}
				model, err := e.resolveModel(modelName)
				if err != nil {
					return nil, fmt.Errorf("ml_unsure: %w", err)
				}
				if text == "" {
					text = e.classifierText()
				}
				return starlark.Bool(model.Unsure(text)), nil
			}),

		// classify returns the predicted label and full distribution.
		"classify": starlark.NewBuiltin("classify",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var modelName, text string
				if err := starlark.UnpackArgs("classify", args, kwargs, "model?", &modelName, "text?", &text); err != nil {
					return nil, err
				}
				model, err := e.resolveModel(modelName)
				if err != nil {
					return nil, fmt.Errorf("classify: %w", err)
				}
				if text == "" {
					text = e.classifierText()
				}

				pred, err := model.Classify(text)
				if err != nil {
					return nil, fmt.Errorf("classify: %w", err)
				}
				return dictOf(
					"label", pred.Label,
					"confidence", pred.Confidence,
					"probabilities", pred.Probabilities,
					"model", model.Name,
				), nil
			}),

		// classify_label is the common case: just the winning label.
		"classify_label": starlark.NewBuiltin("classify_label",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var modelName string
				if err := starlark.UnpackArgs("classify_label", args, kwargs, "model?", &modelName); err != nil {
					return nil, err
				}
				model, err := e.resolveModel(modelName)
				if err != nil {
					return nil, fmt.Errorf("classify_label: %w", err)
				}
				pred, err := model.Classify(e.classifierText())
				if err != nil {
					return nil, fmt.Errorf("classify_label: %w", err)
				}
				return starlark.String(pred.Label), nil
			}),

		// ml_score returns the probability of one class, which is what a
		// threshold rule wants: ml_score("spam") > 0.9.
		"ml_score": starlark.NewBuiltin("ml_score",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var class, modelName, text string
				if err := starlark.UnpackArgs("ml_score", args, kwargs, "class", &class, "model?", &modelName, "text?", &text); err != nil {
					return nil, err
				}
				model, err := e.resolveModel(modelName)
				if err != nil {
					return nil, fmt.Errorf("ml_score: %w", err)
				}
				if text == "" {
					text = e.classifierText()
				}
				score, err := model.ScoreFor(text, class)
				if err != nil {
					return nil, fmt.Errorf("ml_score: %w", err)
				}
				return starlark.Float(score), nil
			}),

		// ml_explain surfaces the terms that drove the classification, so a
		// quarantine decision can be justified to the recipient.
		"ml_explain": starlark.NewBuiltin("ml_explain",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var modelName string
				limit := 10
				if err := starlark.UnpackArgs("ml_explain", args, kwargs, "model?", &modelName, "limit?", &limit); err != nil {
					return nil, err
				}
				model, err := e.resolveModel(modelName)
				if err != nil {
					return nil, fmt.Errorf("ml_explain: %w", err)
				}
				features, err := model.Explain(e.classifierText(), limit)
				if err != nil {
					return nil, fmt.Errorf("ml_explain: %w", err)
				}
				values := make([]starlark.Value, 0, len(features))
				for _, f := range features {
					values = append(values, dictOf("term", f.Term, "weight", f.Weight))
				}
				return starlark.NewList(values), nil
			}),

		// tfidf_score reports how strongly the message resembles a class,
		// expressed as the class probability. It is a readable alias for
		// ml_score in scripts whose intent is similarity rather than
		// classification.
		"tfidf_score": starlark.NewBuiltin("tfidf_score",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var class, modelName string
				if err := starlark.UnpackArgs("tfidf_score", args, kwargs, "class", &class, "model?", &modelName); err != nil {
					return nil, err
				}
				model, err := e.resolveModel(modelName)
				if err != nil {
					return nil, fmt.Errorf("tfidf_score: %w", err)
				}
				score, err := model.ScoreFor(e.classifierText(), class)
				if err != nil {
					return nil, fmt.Errorf("tfidf_score: %w", err)
				}
				return starlark.Float(score), nil
			}),

		// tokenize exposes the analyzer so rules can inspect or count
		// features without a trained model.
		"tokenize": starlark.NewBuiltin("tokenize",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var text string
				ngramMax := 1
				if err := starlark.UnpackArgs("tokenize", args, kwargs, "text?", &text, "ngram_max?", &ngramMax); err != nil {
					return nil, err
				}
				if text == "" {
					text = e.classifierText()
				}
				analyzer := ml.DefaultAnalyzer()
				analyzer.NGramMax = ngramMax
				return stringList(analyzer.Analyze(text)), nil
			}),

		// token_vector returns term frequencies, or TF-IDF weights when a
		// model supplies the fitted vocabulary.
		"token_vector": starlark.NewBuiltin("token_vector",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var modelName, text string
				limit := 50
				if err := starlark.UnpackArgs("token_vector", args, kwargs, "model?", &modelName, "text?", &text, "limit?", &limit); err != nil {
					return nil, err
				}
				if text == "" {
					text = e.classifierText()
				}

				// Without a model, fall back to raw term frequencies so the
				// builtin is still useful in the offline test harness.
				model, err := e.resolveModel(modelName)
				if err != nil {
					counts := ml.TokenCounts(ml.DefaultAnalyzer().Analyze(text))
					weights := make(map[string]float64, len(counts))
					for term, n := range counts {
						weights[term] = float64(n)
					}
					return floatDict(topWeights(weights, limit)), nil
				}

				features := model.Vectorizer.TopFeatures(model.Vectorizer.Transform(text), limit)
				weights := make(map[string]float64, len(features))
				for _, f := range features {
					weights[f.Term] = f.Weight
				}
				return floatDict(weights), nil
			}),

		// -- BERT-style tokenization ---------------------------------------

		"bert_available": nullaryBool("bert_available", func() bool {
			return e.opts.BertTokenizer != nil && e.opts.BertTokenizer.Size() > 0
		}),

		"bert_vocab_size": nullaryInt("bert_vocab_size", func() int {
			return e.opts.BertTokenizer.Size()
		}),

		"bert_tokens": starlark.NewBuiltin("bert_tokens",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var text string
				if err := starlark.UnpackArgs("bert_tokens", args, kwargs, "text?", &text); err != nil {
					return nil, err
				}
				if e.opts.BertTokenizer == nil {
					return nil, fmt.Errorf("bert_tokens: no WordPiece vocabulary loaded; start with --bert-vocab")
				}
				if text == "" {
					text = e.classifierText()
				}
				return stringList(e.opts.BertTokenizer.Tokenize(text)), nil
			}),

		"bert_token_ids": starlark.NewBuiltin("bert_token_ids",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var text string
				maxLen := 0
				addSpecial := true
				if err := starlark.UnpackArgs("bert_token_ids", args, kwargs,
					"text?", &text, "max_len?", &maxLen, "add_special?", &addSpecial); err != nil {
					return nil, err
				}
				if e.opts.BertTokenizer == nil {
					return nil, fmt.Errorf("bert_token_ids: no WordPiece vocabulary loaded; start with --bert-vocab")
				}
				if text == "" {
					text = e.classifierText()
				}
				ids := e.opts.BertTokenizer.Encode(text, addSpecial, maxLen)
				values := make([]starlark.Value, len(ids))
				for i, id := range ids {
					values[i] = starlark.MakeInt(id)
				}
				return starlark.NewList(values), nil
			}),

		// -- Embeddings ----------------------------------------------------

		"embedders": nullaryList("embedders", ml.EmbedderNames),

		"embed": starlark.NewBuiltin("embed",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var backend, text string
				if err := starlark.UnpackArgs("embed", args, kwargs, "backend", &backend, "text?", &text); err != nil {
					return nil, err
				}
				embedder, ok := ml.GetEmbedder(backend)
				if !ok {
					return nil, fmt.Errorf("embed: no embedding backend named %q is registered (have: %s)",
						backend, strings.Join(ml.EmbedderNames(), ", "))
				}
				if text == "" {
					text = e.classifierText()
				}
				vector, err := embedder.Embed(text)
				if err != nil {
					return nil, fmt.Errorf("embed: %w", err)
				}
				values := make([]starlark.Value, len(vector))
				for i, v := range vector {
					values[i] = starlark.Float(float64(v))
				}
				return starlark.NewList(values), nil
			}),

		"embed_similarity": starlark.NewBuiltin("embed_similarity",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var backend, a, c string
				if err := starlark.UnpackArgs("embed_similarity", args, kwargs, "backend", &backend, "a", &a, "b", &c); err != nil {
					return nil, err
				}
				embedder, ok := ml.GetEmbedder(backend)
				if !ok {
					return nil, fmt.Errorf("embed_similarity: no embedding backend named %q is registered", backend)
				}
				va, err := embedder.Embed(a)
				if err != nil {
					return nil, fmt.Errorf("embed_similarity: %w", err)
				}
				vb, err := embedder.Embed(c)
				if err != nil {
					return nil, fmt.Errorf("embed_similarity: %w", err)
				}
				return starlark.Float(ml.DenseCosine(va, vb)), nil
			}),

		// text_similarity compares two strings in the model's TF-IDF space,
		// which is how near-duplicate campaign detection is built.
		"text_similarity": starlark.NewBuiltin("text_similarity",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var a, c, modelName string
				if err := starlark.UnpackArgs("text_similarity", args, kwargs, "a", &a, "b", &c, "model?", &modelName); err != nil {
					return nil, err
				}

				var vectorizer *ml.Vectorizer
				if model, err := e.resolveModel(modelName); err == nil {
					vectorizer = model.Vectorizer
				} else {
					// No model loaded: hash both documents into a shared
					// space so the comparison still works.
					vectorizer = ml.NewHashingVectorizer(1 << 16)
				}
				return starlark.Float(ml.CosineSimilarity(
					vectorizer.Transform(a), vectorizer.Transform(c))), nil
			}),

		// message_similarity compares this message against a reference text.
		"message_similarity": starlark.NewBuiltin("message_similarity",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var reference, modelName string
				if err := starlark.UnpackArgs("message_similarity", args, kwargs, "reference", &reference, "model?", &modelName); err != nil {
					return nil, err
				}
				var vectorizer *ml.Vectorizer
				if model, err := e.resolveModel(modelName); err == nil {
					vectorizer = model.Vectorizer
				} else {
					vectorizer = ml.NewHashingVectorizer(1 << 16)
				}
				return starlark.Float(ml.CosineSimilarity(
					vectorizer.Transform(e.classifierText()),
					vectorizer.Transform(reference))), nil
			}),

		"classifier_text": nullaryStr("classifier_text", e.classifierText),

		// spam_probability is a convenience wrapper for the overwhelmingly
		// common binary spam model.
		"spam_probability": starlark.NewBuiltin("spam_probability",
			func(_ *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
				var modelName string
				if err := starlark.UnpackArgs("spam_probability", args, kwargs, "model?", &modelName); err != nil {
					return nil, err
				}
				model, err := e.resolveModel(modelName)
				if err != nil {
					// Fall back to the externally supplied score so a rule
					// written for a model still functions without one.
					return starlark.Float(msg.SpamScore / 10.0), nil
				}
				score, err := model.ScoreFor(e.classifierText(), "spam")
				if err != nil {
					return nil, fmt.Errorf("spam_probability: %w", err)
				}
				return starlark.Float(score), nil
			}),
	}
}

// topWeights keeps the n highest-weighted entries of a map.
func topWeights(weights map[string]float64, n int) map[string]float64 {
	if n <= 0 || len(weights) <= n {
		return weights
	}

	type pair struct {
		term   string
		weight float64
	}
	pairs := make([]pair, 0, len(weights))
	for term, weight := range weights {
		pairs = append(pairs, pair{term, weight})
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].weight != pairs[j].weight {
			return pairs[i].weight > pairs[j].weight
		}
		return pairs[i].term < pairs[j].term
	})

	out := make(map[string]float64, n)
	for _, p := range pairs[:n] {
		out[p.term] = p.weight
	}
	return out
}

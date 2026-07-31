package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/afterdarksys/mailscript/pkg/ml"
	"github.com/afterdarksys/mailscript/pkg/rules"
	"github.com/spf13/cobra"
)

var trainCmd = &cobra.Command{
	Use:   "train",
	Short: "Train a classification model from labelled mail",
	Long: `Fit a TF-IDF and Naive Bayes classifier over labelled corpora and write
the model to disk for use by the ml_score and classify builtins.

Corpora may be mbox files or Maildir directories. Each --spam and --ham flag
contributes every message it contains under that label; --label lets you
train more than two classes.

A held-out split is scored automatically so the reported accuracy reflects
unseen mail rather than memorised training data.

Examples:
  # Binary spam model
  mailscript train --spam=spam.mbox --ham=ham.mbox --out=spam.json.gz

  # Multi-class model
  mailscript train --label=phish:phish.mbox --label=bulk:bulk.mbox \
    --label=legit:inbox.mbox --out=triage.json.gz

  # Use the model
  mailscript test --script=filter.star --model=spam.json.gz --eml=message.eml`,
	RunE: runTrain,
}

var (
	trainSpam             []string
	trainHam              []string
	trainLabels           []string
	trainOut              string
	trainHoldout          float64
	trainMinDF            int
	trainMaxFeat          int
	trainNGramMax         int
	trainAlpha            float64
	trainHashDim          int
	trainMaxPerSet        int
	trainScorer           string
	trainFeatureSelection string
	trainOSBWindow        int
)

func init() {
	rootCmd.AddCommand(trainCmd)

	f := trainCmd.Flags()
	f.StringSliceVar(&trainSpam, "spam", nil, "mbox or Maildir of spam. Repeatable")
	f.StringSliceVar(&trainHam, "ham", nil, "mbox or Maildir of legitimate mail. Repeatable")
	f.StringSliceVar(&trainLabels, "label", nil, "Additional corpus as label:path. Repeatable")
	f.StringVar(&trainOut, "out", "model.json.gz", "Output path; a .gz suffix compresses the model")
	f.Float64Var(&trainHoldout, "holdout", 0.2, "Fraction of the corpus reserved for evaluation")
	f.IntVar(&trainMinDF, "min-df", 2, "Drop terms appearing in fewer than this many messages")
	f.IntVar(&trainMaxFeat, "max-features", 50000, "Maximum vocabulary size")
	f.IntVar(&trainNGramMax, "ngram-max", 2, "Largest n-gram to extract")
	f.Float64Var(&trainAlpha, "alpha", 1.0, "Additive smoothing parameter")
	f.IntVar(&trainHashDim, "hash-dim", 0, "Use the hashing trick with this many buckets instead of a vocabulary")
	f.IntVar(&trainMaxPerSet, "max-per-corpus", 0, "Cap messages read from each corpus (0 = all)")
	f.StringVar(&trainScorer, "scorer", "fisher", "Classifier scorer: fisher, robinson, or bayes")
	f.StringVar(&trainFeatureSelection, "feature-selection", "chi2", "Feature ranking: chi2 or frequency")
	f.IntVar(&trainOSBWindow, "osb-window", 0, "Emit order-sensitive sparse bigrams up to this token distance (0 disables)")
}

func runTrain(cmd *cobra.Command, args []string) error {
	corpora := map[string][]string{}
	for _, path := range trainSpam {
		corpora["spam"] = append(corpora["spam"], path)
	}
	for _, path := range trainHam {
		corpora["ham"] = append(corpora["ham"], path)
	}
	for _, spec := range trainLabels {
		i := strings.Index(spec, ":")
		if i <= 0 {
			return fmt.Errorf("--label must be given as label:path, got %q", spec)
		}
		label, path := spec[:i], spec[i+1:]
		corpora[label] = append(corpora[label], path)
	}

	if len(corpora) < 2 {
		return fmt.Errorf("at least two labelled corpora are required; pass --spam and --ham, or two --label flags")
	}

	var docs []ml.LabeledDoc
	labels := make([]string, 0, len(corpora))
	for label := range corpora {
		labels = append(labels, label)
	}
	sort.Strings(labels)

	for _, label := range labels {
		count := 0
		for _, path := range corpora[label] {
			loaded, err := loadCorpus(path, label, trainMaxPerSet)
			if err != nil {
				return fmt.Errorf("load %s corpus %q: %w", label, path, err)
			}
			docs = append(docs, loaded...)
			count += len(loaded)
		}
		if count == 0 {
			return fmt.Errorf("corpus for label %q contained no messages", label)
		}
		if verbose {
			fmt.Printf("Loaded %d messages labelled %q\n", count, label)
		}
	}

	analyzer := ml.DefaultAnalyzer()
	analyzer.NGramMax = trainNGramMax
	analyzer.OSBWindow = trainOSBWindow

	opts := ml.TrainOptions{
		Name:             strings.TrimSuffix(filepath.Base(trainOut), filepath.Ext(trainOut)),
		Description:      fmt.Sprintf("trained from %d messages across %d classes", len(docs), len(labels)),
		Analyzer:         analyzer,
		Alpha:            trainAlpha,
		MinDF:            trainMinDF,
		MaxDFRatio:       0.95,
		MaxFeatures:      trainMaxFeat,
		HashDim:          trainHashDim,
		HoldoutRatio:     trainHoldout,
		Seed:             42,
		Scorer:           trainScorer,
		FeatureSelection: trainFeatureSelection,
	}

	model, err := ml.Train(docs, opts)
	if err != nil {
		return err
	}

	if err := model.Save(trainOut); err != nil {
		return err
	}

	if outputJSON {
		payload := map[string]interface{}{
			"output":   trainOut,
			"messages": len(docs),
			"classes":  model.Classes,
			"features": model.Vectorizer.NumFeatures(),
		}
		if model.Metrics != nil {
			payload["accuracy"] = model.Metrics.Accuracy
			payload["per_class"] = model.Metrics.PerClass
		}
		return printJSON(payload)
	}

	fmt.Printf("\nModel written to %s\n", trainOut)
	fmt.Printf("Messages: %d\n", len(docs))
	fmt.Printf("Classes:  %s\n", strings.Join(model.Classes, ", "))
	fmt.Printf("Features: %d\n", model.Vectorizer.NumFeatures())

	if model.Metrics != nil {
		fmt.Printf("\nHeld-out evaluation (%d messages):\n", model.Metrics.Samples)
		fmt.Printf("Accuracy: %.1f%%\n", model.Metrics.Accuracy*100)
		for _, label := range model.Classes {
			m := model.Metrics.PerClass[label]
			fmt.Printf("%-12s precision %.2f  recall %.2f  f1 %.2f  (n=%d)\n",
				label, m.Precision, m.Recall, m.F1, m.Support)
		}

		// A model that misclassifies legitimate mail is worse than no model,
		// so call that out rather than reporting a single accuracy figure.
		if ham, ok := model.Metrics.PerClass["ham"]; ok && ham.Recall < 0.95 && ham.Support > 0 {
			fmt.Printf("\n  WARNING: %.0f%% of legitimate mail was misclassified. "+
				"Add more ham examples before using this model to reject.\n",
				(1-ham.Recall)*100)
		}
	}

	return nil
}

// loadCorpus reads every message from an mbox file or Maildir directory.
func loadCorpus(path, label string, limit int) ([]ml.LabeledDoc, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return loadMaildirCorpus(path, label, limit)
	}
	return loadMboxCorpus(path, label, limit)
}

func loadMboxCorpus(path, label string, limit int) ([]ml.LabeledDoc, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var docs []ml.LabeledDoc
	var buf bytes.Buffer

	flush := func() {
		if buf.Len() == 0 {
			return
		}
		if doc, ok := messageToDoc(buf.Bytes(), label); ok {
			docs = append(docs, doc)
		}
		buf.Reset()
	}

	reader := bufio.NewReader(file)
	for {
		line, err := reader.ReadString('\n')

		// An mbox message starts at a line beginning "From ".
		if strings.HasPrefix(line, "From ") {
			flush()
			if limit > 0 && len(docs) >= limit {
				return docs, nil
			}
			if err == io.EOF {
				break
			}
			continue
		}

		buf.WriteString(line)

		if err != nil {
			if err == io.EOF {
				flush()
				break
			}
			return nil, err
		}
	}

	return docs, nil
}

func loadMaildirCorpus(path, label string, limit int) ([]ml.LabeledDoc, error) {
	var docs []ml.LabeledDoc

	for _, sub := range []string{"cur", "new", "."} {
		dir := filepath.Join(path, sub)
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			if limit > 0 && len(docs) >= limit {
				return docs, nil
			}

			raw, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				continue
			}
			if doc, ok := messageToDoc(raw, label); ok {
				docs = append(docs, doc)
			}
		}
	}

	return docs, nil
}

// messageToDoc renders a message into the text the classifier trains on. It
// must match what the runtime feeds the model, or the model sees a different
// feature distribution in production than it did in training.
func messageToDoc(raw []byte, label string) (ml.LabeledDoc, bool) {
	ctx, err := rules.ParseMessage(raw)
	if err != nil {
		return ml.LabeledDoc{}, false
	}

	var sb strings.Builder
	if subject := ctx.Get("Subject"); subject != "" {
		sb.WriteString("subject: ")
		sb.WriteString(subject)
		sb.WriteString("\n")
	}
	if from := ctx.Get("From"); from != "" {
		sb.WriteString("from: ")
		sb.WriteString(from)
		sb.WriteString("\n")
	}
	sb.WriteString(ctx.SearchText())

	text := strings.TrimSpace(sb.String())
	if text == "" {
		return ml.LabeledDoc{}, false
	}
	return ml.LabeledDoc{Label: label, Text: text}, true
}

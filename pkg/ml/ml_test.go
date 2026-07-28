package ml

import (
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestAnalyzerCollapsesURLsAndEmails(t *testing.T) {
	a := DefaultAnalyzer()
	tokens := a.Analyze("Visit https://promo.example/a/b/c or mail sales@promo.example today")

	joined := strings.Join(tokens, " ")
	if !strings.Contains(joined, "url:promo.example") {
		t.Errorf("expected a url host feature, got %v", tokens)
	}
	if !strings.Contains(joined, "emaildom:promo.example") {
		t.Errorf("expected an email domain feature, got %v", tokens)
	}
	// The randomised path must not survive as its own feature.
	if strings.Contains(joined, "/a/b/c") {
		t.Errorf("URL paths should be collapsed, got %v", tokens)
	}
}

func TestAnalyzerRecordsShoutingAndPunctuation(t *testing.T) {
	tokens := DefaultAnalyzer().Analyze("FREE MONEY!!! act now")
	joined := strings.Join(tokens, " ")

	if !strings.Contains(joined, "__caps__") {
		t.Errorf("expected a shouting feature, got %v", tokens)
	}
	if !strings.Contains(joined, "__repbang__") {
		t.Errorf("expected a repeated-punctuation feature (__repbang__), got %v", tokens)
	}
}

func TestAnalyzerNGrams(t *testing.T) {
	a := DefaultAnalyzer()
	a.NGramMin, a.NGramMax = 1, 2
	a.Stopwords = nil

	tokens := a.Analyze("wire transfer request")
	if !contains(tokens, "wire_transfer") {
		t.Errorf("expected a bigram, got %v", tokens)
	}
	if !contains(tokens, "wire") {
		t.Errorf("expected unigrams alongside bigrams, got %v", tokens)
	}
}

func TestVectorizerFitAndTransform(t *testing.T) {
	docs := []string{
		"cheap pills online pharmacy",
		"cheap watches online store",
		"meeting notes from monday",
		"meeting agenda for monday",
	}

	v := NewVectorizer()
	v.MinDF = 1
	v.Fit(docs)

	if v.NumFeatures() == 0 {
		t.Fatal("expected a non-empty vocabulary")
	}

	vec := v.Transform("cheap pills online")
	if vec.Len() == 0 {
		t.Fatal("expected non-zero features")
	}

	// L2 normalisation is on by default.
	if norm := vec.Norm(); math.Abs(norm-1.0) > 1e-9 {
		t.Errorf("expected a unit-length vector, got norm %v", norm)
	}

	// Indices must be ascending for the sparse operations to be correct.
	for i := 1; i < len(vec.Indices); i++ {
		if vec.Indices[i] <= vec.Indices[i-1] {
			t.Fatalf("indices are not ascending: %v", vec.Indices)
		}
	}
}

func TestVectorizerIsDeterministic(t *testing.T) {
	docs := []string{"alpha beta gamma", "beta gamma delta", "gamma delta epsilon"}

	first := NewVectorizer()
	first.MinDF = 1
	first.Fit(docs)

	second := NewVectorizer()
	second.MinDF = 1
	second.Fit(docs)

	for term, idx := range first.Vocab {
		if second.Vocab[term] != idx {
			t.Fatalf("vocabulary is not reproducible: %q mapped to %d then %d",
				term, idx, second.Vocab[term])
		}
	}
}

func TestHashingVectorizerNeedsNoFit(t *testing.T) {
	v := NewHashingVectorizer(1024)

	a := v.Transform("cheap pills online")
	b := v.Transform("cheap pills online")

	if a.Len() == 0 {
		t.Fatal("expected features from the hashing vectorizer")
	}
	if CosineSimilarity(a, b) < 0.999 {
		t.Error("identical documents must hash identically")
	}
}

func TestCosineSimilarity(t *testing.T) {
	v := NewHashingVectorizer(4096)

	same := CosineSimilarity(
		v.Transform("quarterly revenue report attached"),
		v.Transform("quarterly revenue report attached"))
	if same < 0.999 {
		t.Errorf("identical text should score ~1, got %v", same)
	}

	different := CosineSimilarity(
		v.Transform("quarterly revenue report"),
		v.Transform("buy discount pharmaceuticals now"))
	if different > 0.3 {
		t.Errorf("unrelated text should score low, got %v", different)
	}
}

// -- Classification ---------------------------------------------------------

func spamCorpus() []LabeledDoc {
	spam := []string{
		"cheap pills online pharmacy no prescription needed",
		"you have won the lottery claim your prize now",
		"discount watches rolex replica free shipping",
		"urgent verify your account or it will be suspended",
		"make money fast working from home guaranteed income",
		"free viagra cialis discount pharmacy online",
		"congratulations you are the winner claim prize money",
		"limited time offer act now discount pills",
		"your account will be suspended verify immediately",
		"earn cash fast no experience required work from home",
	}
	ham := []string{
		"can we move the monday meeting to tuesday afternoon",
		"attached is the quarterly revenue report for review",
		"thanks for sending the notes from yesterday standup",
		"the deployment finished successfully all tests pass",
		"please review the pull request when you get a chance",
		"lunch tomorrow at the usual place around noon",
		"here are the meeting notes from the planning session",
		"the quarterly report has been updated with new figures",
		"could you take a look at the failing integration test",
		"reminder about the team retrospective on friday",
	}

	var docs []LabeledDoc
	for _, s := range spam {
		docs = append(docs, LabeledDoc{Label: "spam", Text: s})
	}
	for _, h := range ham {
		docs = append(docs, LabeledDoc{Label: "ham", Text: h})
	}
	return docs
}

func TestTrainAndClassify(t *testing.T) {
	opts := DefaultTrainOptions()
	opts.MinDF = 1
	opts.HoldoutRatio = 0

	model, err := Train(spamCorpus(), opts)
	if err != nil {
		t.Fatalf("Train: %v", err)
	}

	spam, err := model.Classify("claim your free prize money now discount pills")
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if spam.Label != "spam" {
		t.Errorf("expected spam, got %s (%v)", spam.Label, spam.Probabilities)
	}

	ham, err := model.Classify("can we reschedule the meeting to review the report")
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}
	if ham.Label != "ham" {
		t.Errorf("expected ham, got %s (%v)", ham.Label, ham.Probabilities)
	}
}

func TestProbabilitiesSumToOne(t *testing.T) {
	opts := DefaultTrainOptions()
	opts.MinDF = 1
	opts.HoldoutRatio = 0

	model, err := Train(spamCorpus(), opts)
	if err != nil {
		t.Fatalf("Train: %v", err)
	}

	pred, err := model.Classify("some completely unseen text about nothing")
	if err != nil {
		t.Fatalf("Classify: %v", err)
	}

	total := 0.0
	for _, p := range pred.Probabilities {
		if p < 0 || p > 1 {
			t.Errorf("probability out of range: %v", p)
		}
		total += p
	}
	if math.Abs(total-1.0) > 1e-9 {
		t.Errorf("probabilities should sum to 1, got %v", total)
	}
}

func TestTrainRejectsSingleClassCorpus(t *testing.T) {
	_, err := Train([]LabeledDoc{
		{Label: "spam", Text: "one"},
		{Label: "spam", Text: "two"},
	}, DefaultTrainOptions())

	if err == nil {
		t.Fatal("expected an error for a single-class corpus")
	}
	if !strings.Contains(err.Error(), "class") {
		t.Errorf("expected the error to mention classes, got %v", err)
	}
}

func TestTrainRejectsEmptyCorpus(t *testing.T) {
	if _, err := Train(nil, DefaultTrainOptions()); err == nil {
		t.Fatal("expected an error for an empty corpus")
	}
}

func TestUntrainedClassifierErrors(t *testing.T) {
	nb := NewNaiveBayes()
	if _, err := nb.Predict(SparseVector{}); err != ErrNotTrained {
		t.Errorf("expected ErrNotTrained, got %v", err)
	}
}

func TestModelRoundTrip(t *testing.T) {
	opts := DefaultTrainOptions()
	opts.MinDF = 1
	opts.HoldoutRatio = 0

	model, err := Train(spamCorpus(), opts)
	if err != nil {
		t.Fatalf("Train: %v", err)
	}

	for _, name := range []string{"model.json", "model.json.gz"} {
		path := filepath.Join(t.TempDir(), name)
		if err := model.Save(path); err != nil {
			t.Fatalf("Save(%s): %v", name, err)
		}

		loaded, err := LoadModel(path)
		if err != nil {
			t.Fatalf("LoadModel(%s): %v", name, err)
		}

		text := "claim your free prize money now"
		before, _ := model.Classify(text)
		after, err := loaded.Classify(text)
		if err != nil {
			t.Fatalf("Classify after load: %v", err)
		}
		if before.Label != after.Label {
			t.Errorf("%s: label changed across save/load: %s then %s", name, before.Label, after.Label)
		}
		if math.Abs(before.Confidence-after.Confidence) > 1e-9 {
			t.Errorf("%s: confidence changed across save/load", name)
		}
	}
}

func TestLoadModelRejectsGarbage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := LoadModel(path); err == nil {
		t.Fatal("expected an error for a malformed model file")
	}
}

func TestEvaluateProducesMetrics(t *testing.T) {
	opts := DefaultTrainOptions()
	opts.MinDF = 1
	opts.HoldoutRatio = 0

	model, err := Train(spamCorpus(), opts)
	if err != nil {
		t.Fatalf("Train: %v", err)
	}

	metrics := model.Evaluate(spamCorpus())
	if metrics.Samples != 20 {
		t.Errorf("expected 20 samples, got %d", metrics.Samples)
	}
	if metrics.Accuracy < 0.8 {
		t.Errorf("training accuracy should be high, got %v", metrics.Accuracy)
	}
	if _, ok := metrics.PerClass["spam"]; !ok {
		t.Error("expected per-class metrics for spam")
	}
}

func TestExplainReturnsTerms(t *testing.T) {
	opts := DefaultTrainOptions()
	opts.MinDF = 1
	opts.HoldoutRatio = 0

	model, err := Train(spamCorpus(), opts)
	if err != nil {
		t.Fatalf("Train: %v", err)
	}

	features, err := model.Explain("free prize money pills", 5)
	if err != nil {
		t.Fatalf("Explain: %v", err)
	}
	if len(features) == 0 {
		t.Fatal("expected explanatory features")
	}
	for i := 1; i < len(features); i++ {
		if features[i].Weight > features[i-1].Weight {
			t.Error("features should be ordered by descending weight")
		}
	}
}

func TestRegistry(t *testing.T) {
	opts := DefaultTrainOptions()
	opts.MinDF = 1
	opts.HoldoutRatio = 0
	model, _ := Train(spamCorpus(), opts)

	r := NewRegistry()
	if _, ok := r.Default(); ok {
		t.Error("an empty registry has no default")
	}

	r.Add("spam", model)
	if _, ok := r.Default(); !ok {
		t.Error("a single registered model should be the default")
	}

	r.Add("other", model)
	if _, ok := r.Default(); ok {
		t.Error("two models with no explicit default should be ambiguous")
	}

	r.Add("default", model)
	if _, ok := r.Default(); !ok {
		t.Error("an explicit default should resolve")
	}
	if len(r.Names()) != 3 {
		t.Errorf("expected three names, got %v", r.Names())
	}
}

// -- BERT tokenizer ---------------------------------------------------------

func testTokenizer() *BertTokenizer {
	vocab := []string{
		"[PAD]", "[UNK]", "[CLS]", "[SEP]", "[MASK]",
		"the", "quick", "brown", "fox", "un", "##aff", "##able",
		"play", "##ing", "invoice", "attach", "##ed", ".", ",", "!",
	}
	return NewBertTokenizer(vocab, true)
}

func TestBertWordPieceSegmentation(t *testing.T) {
	tok := testTokenizer()

	got := tok.Tokenize("unaffable")
	want := []string{"un", "##aff", "##able"}
	if len(got) != len(want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %v, got %v", want, got)
		}
	}
}

func TestBertUnknownWordsBecomeUNK(t *testing.T) {
	tok := testTokenizer()

	got := tok.Tokenize("zzzzyx")
	if len(got) != 1 || got[0] != TokenUnknown {
		t.Errorf("expected [UNK], got %v", got)
	}
}

func TestBertSplitsPunctuation(t *testing.T) {
	tok := testTokenizer()

	got := tok.Tokenize("the fox.")
	if !contains(got, ".") {
		t.Errorf("punctuation should be its own token, got %v", got)
	}
}

func TestBertEncodeAddsSpecialTokensAndPads(t *testing.T) {
	tok := testTokenizer()

	ids := tok.Encode("the quick brown fox", true, 10)
	if len(ids) != 10 {
		t.Fatalf("expected padding to length 10, got %d", len(ids))
	}
	if ids[0] != 2 { // [CLS]
		t.Errorf("expected [CLS] first, got %d", ids[0])
	}

	mask := tok.AttentionMask(ids)
	if len(mask) != len(ids) {
		t.Fatal("mask and ids must be the same length")
	}
	if mask[len(mask)-1] != 0 {
		t.Error("padding positions must be masked out")
	}
}

func TestBertEncodeTruncates(t *testing.T) {
	tok := testTokenizer()

	ids := tok.Encode("the quick brown fox playing the quick brown fox", true, 5)
	if len(ids) != 5 {
		t.Fatalf("expected truncation to 5, got %d", len(ids))
	}
}

func TestBertDecodeRejoinsSubwords(t *testing.T) {
	tok := testTokenizer()

	ids := tok.Encode("unaffable", false, 0)
	if got := tok.Decode(ids); got != "unaffable" {
		t.Errorf("expected round-trip to unaffable, got %q", got)
	}
}

func TestLoadBertVocabRejectsMissingFile(t *testing.T) {
	if _, err := LoadBertVocab(filepath.Join(t.TempDir(), "nope.txt"), true); err == nil {
		t.Fatal("expected an error for a missing vocabulary")
	}
}

func TestGoLearnStubReportsUnavailable(t *testing.T) {
	// Without the build tag this must fail cleanly rather than panic.
	if GoLearnAvailable() {
		t.Skip("built with -tags golearn")
	}
	if _, err := TrainGoLearn(spamCorpus(), GoLearnOptions{}); err == nil {
		t.Fatal("expected an error without the golearn build tag")
	}
}

func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

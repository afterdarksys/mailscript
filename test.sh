#!/bin/bash
# Test harness for MailScript. Builds if needed, runs the Go test suite, then
# exercises the CLI end to end.
set -e

cd "$(dirname "$0")"

echo "Running Go tests"
go test ./...
echo ""

if [ ! -f "./mailscript" ]; then
    echo "Building mailscript"
    ./build.sh
    echo ""
fi

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

echo "Linting bundled examples"
for script in examples/*.star; do
    printf '  %-40s' "$(basename "$script")"
    ./mailscript lint --script="$script" >/dev/null && echo "ok"
done
echo ""

echo "Test 1: spam keyword detection"
./mailscript test \
    --script=examples/spam-filter.star \
    --from="spam@evil.example" \
    --subject="Buy Viagra Now" \
    --verbose
echo ""

echo "Test 2: trusted sender"
./mailscript test \
    --script=examples/spam-filter.star \
    --from="admin@example.com" \
    --subject="Monthly Report" \
    --verbose
echo ""

echo "Test 3: header validation catches a spoofed display name"
cat > "$WORK/spoof.eml" <<'MSG'
From: "security@paypal.com" <attacker@evil.example>
To: victim@example.net
Subject: Verify your account
Date: Mon, 27 Jul 2026 10:00:00 +0000

Click here.
MSG
./mailscript inspect --eml="$WORK/spoof.eml" | grep -q SPOOF_DISPLAY_NAME_ADDR
echo "  display-name spoofing detected"
echo ""

echo "Test 4: forged Authentication-Results is not believed"
cat > "$WORK/forged.eml" <<'MSG'
From: ceo@bank.example
To: victim@example.net
Subject: Wire request
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass

Please wire the funds.
MSG
./mailscript inspect --eml="$WORK/forged.eml" --trusted-authserv=mx.ours.example \
    | grep -q "UNTRUSTED"
echo "  untrusted authentication header flagged"
echo ""

echo "Test 5: classifier training and scoring"
for i in 1 2 3 4 5 6 7 8 9 10; do
    printf 'From s@evil.example Mon Jul 27 10:00:00 2026\nFrom: s@evil.example\nSubject: cheap pills discount prize winner %s\n\nclaim your free prize money now discount pills\n\n' "$i"
done > "$WORK/spam.mbox"
for i in 1 2 3 4 5 6 7 8 9 10; do
    printf 'From c@work.example Mon Jul 27 10:00:00 2026\nFrom: c@work.example\nSubject: quarterly report meeting notes %s\n\nplease review the attached quarterly report before the meeting\n\n' "$i"
done > "$WORK/ham.mbox"

./mailscript train --spam="$WORK/spam.mbox" --ham="$WORK/ham.mbox" \
    --out="$WORK/model.json.gz" --min-df=1 --holdout=0 >/dev/null
echo "  model trained"

cat > "$WORK/ml.star" <<'RULE'
def evaluate():
    if ml_score("spam") > 0.6:
        quarantine()
        return
    accept()
RULE
./mailscript test --script="$WORK/ml.star" --model="$WORK/model.json.gz" \
    --subject="claim your free prize money" --body="discount pills winner" \
    | grep -q quarantine
echo "  classifier flagged spam"
echo ""

echo "Test 6: mbox processing"
./mailscript process --script=examples/spam-filter.star --mbox="$WORK/spam.mbox" --json >/dev/null
echo "  mbox processed"
echo ""

echo "Test 7: builtin registry"
COUNT=$(./mailscript builtins | tail -1 | awk "{print \$1}")
echo "  $COUNT builtins registered"
echo ""

echo "All tests passed"

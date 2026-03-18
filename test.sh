#!/bin/bash
set -e

echo "🧪 Running MailScript Tests"
echo ""

# Build first
if [ ! -f "./mailscript" ]; then
    echo "🔨 Building mailscript..."
    ./build.sh
    echo ""
fi

# Test 1: Basic spam filter
echo "Test 1: Spam detection"
./mailscript test \
    --script=examples/spam-filter.star \
    --from="spam@evil.com" \
    --subject="Buy Viagra Now!!!" \
    --verbose

echo ""
echo "---"
echo ""

# Test 2: Trusted sender
echo "Test 2: Trusted sender"
./mailscript test \
    --script=examples/spam-filter.star \
    --from="admin@example.com" \
    --subject="Monthly Report" \
    --verbose

echo ""
echo "---"
echo ""

# Test 3: Process sample mbox (if exists)
if [ -f "examples/sample.mbox" ]; then
    echo "Test 3: Process sample mbox"
    ./mailscript process \
        --script=examples/spam-filter.star \
        --mbox=examples/sample.mbox \
        --verbose
    echo ""
fi

echo "✅ All tests passed!"

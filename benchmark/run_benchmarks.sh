#!/usr/bin/env bash
set -e

echo "=============================================="
echo " PII-Shield Performance Benchmark Tool"
echo "=============================================="

PAYLOAD_FILE="payload.json"
LINES=500000

echo "1. Generating $LINES lines of test logs ($PAYLOAD_FILE)..."
if [ ! -f "$PAYLOAD_FILE" ]; then
  # Write one sample line then duplicate it
  echo '{"timestamp": "2023-11-20T12:00:00Z", "level": "INFO", "message": "User login attempt", "user_id": "123e4567-e89b-12d3-a456-426614174000", "token": "abcD123xyz890", "ip": "192.168.1.1", "credit_card": "4111111111111111"}' > sample.txt
  awk -v n=$LINES '{for(i=1;i<=n;i++) print}' sample.txt > $PAYLOAD_FILE
  rm sample.txt
fi

FILE_SIZE=$(du -kh "$PAYLOAD_FILE" | cut -f1)
echo "   Payload generated. Size: $FILE_SIZE"

# Compile Current Branch (With new hybrid optimizations)
echo "2. Compiling current branch (New Features)..."
/opt/homebrew/bin/go build -o pii-shield-new ../cmd/cleaner/main.go

# Compile Old Dev Branch (Before Phase 1)
# We will clone to a temp directory to avoid modifying current tree
echo "3. Cloning main branch to compile old version (Baseline)..."
TMP_DIR=$(mktemp -d)
git clone .. $TMP_DIR --quiet
cd $TMP_DIR
git checkout origin/main --quiet
/opt/homebrew/bin/go build -o pii-shield-old cmd/cleaner/main.go
cd - > /dev/null
cp $TMP_DIR/pii-shield-old .
rm -rf $TMP_DIR

echo "----------------------------------------------"
echo " RUNNING BENCHMARKS"
echo "----------------------------------------------"

export PII_METRICS_ENABLED=false

echo ">>> Old Version (Baseline)"
time ./pii-shield-old < $PAYLOAD_FILE > /dev/null

echo ""
echo ">>> New Version (With Safeguards & Hybrid Scoring)"
time ./pii-shield-new < $PAYLOAD_FILE > /dev/null

echo "=============================================="
echo "Cleaning up..."
rm pii-shield-new pii-shield-old $PAYLOAD_FILE old_stats.txt new_stats.txt || true
echo "Done."

#!/usr/bin/env bash
# Run the adaptor-faest size report and criterion benchmarks, then write
# median timings + signature sizes to a CSV.
#
# Reads benchmark medians from criterion's per-bench estimates.json rather
# than parsing its human-readable output.
#
# Usage: ./run-benchmarks.sh [output.csv]   (default: bench-results.csv)
# Requires: jq

set -euo pipefail

cd "$(dirname "$0")"

OUT="${1:-bench-results.csv}"
VARIANT="FAEST128f"
GROUP="adaptor_faest128f"

SIZE_LOG=$(mktemp)
trap 'rm -f "$SIZE_LOG"' EXIT

echo "[1/2] Running size report..."
cargo run --release --quiet --bin report-signature-size 2>&1 | tee "$SIZE_LOG"

echo
echo "[2/2] Running benchmarks (this takes a few minutes)..."
cargo bench --quiet

echo
echo "Parsing results into $OUT..."

# Size in bytes from the size binary's plain output.
get_size() {
  grep "\[$1\]" "$SIZE_LOG" | grep -oE '[0-9]+ B' | grep -oE '[0-9]+'
}

# Median in ms from criterion's per-bench estimates (point_estimate is in ns).
get_median_ms() {
  jq -r '.median.point_estimate / 1e6' "target/criterion/$GROUP/$1/new/estimates.json"
}

{
  echo "variant,step,time_median_ms,size_bytes"
  for step in keygen pre_sign pre_ver adapt ver sign ext; do
    t=$(get_median_ms "$step")
    case "$step" in
      pre_sign) sz=$(get_size as_pre_sign) ;;
      adapt)    sz=$(get_size as_adapt) ;;
      sign)     sz=$(get_size as_sign) ;;
      *)        sz="" ;;
    esac
    printf "%s,%s,%s,%s\n" "$VARIANT" "$step" "$t" "$sz"
  done
} > "$OUT"

echo "Wrote $OUT:"
cat "$OUT"

#!/usr/bin/env bash
# Run the adaptor-faest size report and criterion benchmarks, then write
# median timings + signature sizes to a CSV for both adaptor variants.
#
# Reads benchmark medians from criterion's per-bench estimates.json rather
# than parsing its human-readable output.
#
# Usage: ./run-benchmarks.sh [output.csv]   (default: bench-results.csv)
# Requires: jq

set -euo pipefail

cd "$(dirname "$0")"

export RUSTFLAGS="-C target-cpu=native"

OUT="${1:-bench-results.csv}"
VARIANTS=("FAEST128f" "FAEST128f-instance-hiding")
BENCH_GROUPS=("adaptor_faest128f" "instance_hiding_adaptor_faest128f")
SIZE_TITLES=("FAEST128f standard adaptor" "FAEST128f instance-hiding adaptor")

SIZE_LOG=$(mktemp)
trap 'rm -f "$SIZE_LOG"' EXIT

echo "[1/2] Running size report..."
cargo run --release --quiet --bin report-signature-size 2>&1 | tee "$SIZE_LOG"

echo
echo "[2/2] Running benchmarks (this takes a few minutes)..."
cargo bench --quiet

echo
echo "Parsing results into $OUT..."

# Size in bytes from the matching size-report block.
get_size() {
  local title="$1"
  local tag="$2"
  awk -v title="$title" -v tag="[$tag]" '
    $0 == title { in_block = 1; next }
    in_block && $0 !~ /^ / { exit }
    in_block && index($0, tag) { print }
  ' "$SIZE_LOG" | grep -oE '[0-9]+ B' | grep -oE '[0-9]+'
}

# Median in ms from criterion's per-bench estimates (point_estimate is in ns).
get_median_ms() {
  local group="$1"
  local step="$2"
  local estimate
  estimate=$(find "target/criterion/$group/$step" -mindepth 3 -maxdepth 3 -path '*/new/estimates.json' -print -quit)
  if [[ -z "$estimate" ]]; then
    estimate="target/criterion/$group/$step/new/estimates.json"
  fi
  jq -r '.median.point_estimate / 1e6' "$estimate"
}

{
  echo "variant,step,time_median_ms,size_bytes"
  for i in "${!VARIANTS[@]}"; do
    variant="${VARIANTS[$i]}"
    group="${BENCH_GROUPS[$i]}"
    size_title="${SIZE_TITLES[$i]}"
    for step in keygen pre_sign pre_ver adapt ver sign ext; do
      t=$(get_median_ms "$group" "$step")
      case "$step" in
        keygen)   sz=$(get_size "$size_title" as_keygen) ;;
        pre_sign) sz=$(get_size "$size_title" as_pre_sign) ;;
        adapt)    sz=$(get_size "$size_title" as_adapt) ;;
        sign)     sz=$(get_size "$size_title" as_sign) ;;
        *)        sz="" ;;
      esac
      printf "%s,%s,%s,%s\n" "$variant" "$step" "$t" "$sz"
    done
  done
} > "$OUT"

echo "Wrote $OUT:"
cat "$OUT"

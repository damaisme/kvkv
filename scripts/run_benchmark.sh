#!/usr/bin/env bash
set -e

echo "=========================================================="
echo "      Running Automated kvkv Pure Lookup Benchmark Suite"
echo "=========================================================="

ENTRIES_LIST=(1000 10000 100000)
HIT_RATIOS=(1.0 0.9 0.5 0.0)
LOOKUPS=262144
SEED=12345

OUTPUT_CSV="benchmark_results.csv"

echo "implementation,entries,lookups,hit_ratio,elapsed_ns,avg_ns,throughput_mlookup_s,hits,misses,checksum" > "$OUTPUT_CSV"

for entries in "${ENTRIES_LIST[@]}"; do
    for ratio in "${HIT_RATIOS[@]}"; do
        echo "Running: entries=$entries, hit_ratio=$ratio, lookups=$LOOKUPS..."
        ./bench/benchmark_runner \
            --entries "$entries" \
            --lookups "$LOOKUPS" \
            --hit-ratio "$ratio" \
            --seed "$SEED" \
            --csv \
            --no-header >> "$OUTPUT_CSV"
    done
done

echo ""
echo "Benchmark suite completed successfully!"
echo "Results saved to $OUTPUT_CSV"
echo ""
echo "Summary Sample:"
cat "$OUTPUT_CSV" | head -n 15

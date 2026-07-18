#!/usr/bin/env bash
# Simplified Oraculum pipeline runner with retry logic for rate limits
# Runs ingest → classify → oracle → harness for all repos with VHX results

ORACULUM_ROOT="/home/trieudai/Oraculum"
VHX_ROOT="/home/trieudai/VulnHunterX"
REPOS_DIR="$VHX_ROOT/benchmarks/datasets/realvuln/repos"
OUTPUT_DIR="$ORACULUM_ROOT/output/python"
LOG_DIR="$ORACULUM_ROOT/OR_env/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$LOG_DIR" "$OUTPUT_DIR"
cd "$ORACULUM_ROOT"

# Load .env directly (override inherited vars)
set -a && source .env && set +a
source .venv/bin/activate

echo "=== Env ==="
echo "LLM_MODEL=$LLM_MODEL  OPENAI_API_BASE=$OPENAI_API_BASE"

# Retry wrapper — retries a command up to $1 times with backoff
retry() {
    local max_attempts=$1
    shift
    local cmd=("$@")
    local attempt=1
    local delay=10
    while [ "$attempt" -le "$max_attempts" ]; do
        "${cmd[@]}" && return 0
        local exitcode=$?
        if grep -qi "Rate limit\|rate_limit\|too many requests" "$LOGFILE" 2>/dev/null; then
            echo "  [RATE LIMITED] attempt $attempt/$max_attempts, waiting ${delay}s..."
            sleep "$delay"
            delay=$((delay * 2))
            attempt=$((attempt + 1))
        else
            return "$exitcode"
        fi
    done
    return 1
}

# Get repos with Python files and VHX results
REPOS=""
for gt_dir in "$VHX_ROOT/benchmarks/datasets/realvuln/ground-truth"/*/; do
    repo=$(basename "$gt_dir")
    repo_path="$REPOS_DIR/$repo"
    vhx_out="$VHX_ROOT/output/python/$repo/verification_results"
    py_count=$(find "$repo_path" -name "*.py" -type f 2>/dev/null | wc -l)
    if [ "$py_count" -gt 0 ] && [ -d "$vhx_out" ]; then
        REPOS="$REPOS $repo"
    fi
done
TOTAL=$(echo $REPOS | wc -w)
echo "Found $TOTAL repos to process"
echo "Start: $(date)"
echo ""

COUNT=0
for repo in $REPOS; do
    COUNT=$((COUNT + 1))
    echo "[$COUNT/$TOTAL] ===== $repo ====="

    vhx_out="$VHX_ROOT/output/python/$repo/verification_results"
    tp_count=$(ls "$vhx_out"/*.json 2>/dev/null | grep -v "summary\|report" | wc -l)
    echo "  TP findings: $tp_count"

    # Resume guard: skip if already fully processed
    if [ -f "$OUTPUT_DIR/python/$repo/fuzz_targets/status.json" ]; then
        done_count=$(ls "$OUTPUT_DIR/python/$repo/fuzz_targets"/*.py 2>/dev/null | wc -l)
        echo "  [SKIP] already done ($done_count harnesses)"
        continue
    fi

    LOGFILE="$LOG_DIR/pipeline_${repo}_${TIMESTAMP}.log"

    # Ingest (no LLM, no rate limit)
    echo "  [INGEST] $(date)"
    timeout 300 oraculum ingest --vhx-root "$VHX_ROOT" --repo "$repo" --output-dir "$OUTPUT_DIR" --force \
        >> "$LOGFILE" 2>&1
    if [ $? -ne 0 ]; then
        echo "  [INGEST FAIL]"
        continue
    fi

    # Classify (LLM — Python retry handles rate limits internally)
    echo "  [CLASSIFY] $(date)"
    timeout 900 oraculum classify --repo "$repo" --output-dir "$OUTPUT_DIR" --force \
        >> "$LOGFILE" 2>&1
    c_gen=$(python3 -c "
import json
try:
    d=json.load(open('$OUTPUT_DIR/python/$repo/classifications/status.json'))
    print(d.get('counts',{}).get('generated',0))
except: print(0)
" 2>/dev/null)
    c_fail=$(python3 -c "
import json
try:
    d=json.load(open('$OUTPUT_DIR/python/$repo/classifications/status.json'))
    print(d.get('counts',{}).get('failed',0))
except: print(0)
" 2>/dev/null)
    if [ "$c_gen" = "0" ]; then
        echo "  [CLASSIFY FAIL] 0/$((c_gen + c_fail)) generated"
        continue
    fi
    echo "  [CLASSIFY] $c_gen generated ($c_fail failed)"
    sleep 1

    # Oracle (LLM)
    echo "  [ORACLE] $(date)"
    timeout 900 oraculum oracle --repo "$repo" --output-dir "$OUTPUT_DIR" --force \
        >> "$LOGFILE" 2>&1
    o_gen=$(python3 -c "
import json
try:
    d=json.load(open('$OUTPUT_DIR/python/$repo/fuzz_oracles/status.json'))
    print(d.get('counts',{}).get('generated',0))
except: print(0)
" 2>/dev/null)
    o_fail=$(python3 -c "
import json
try:
    d=json.load(open('$OUTPUT_DIR/python/$repo/fuzz_oracles/status.json'))
    print(d.get('counts',{}).get('failed',0))
except: print(0)
" 2>/dev/null)
    if [ "$o_gen" = "0" ]; then
        echo "  [ORACLE FAIL] 0/$((o_gen + o_fail)) generated"
        continue
    fi
    echo "  [ORACLE] $o_gen generated ($o_fail failed)"
    sleep 1

    # Harness (LLM)
    echo "  [HARNESS] $(date)"
    timeout 900 oraculum harness --repo "$repo" --output-dir "$OUTPUT_DIR" \
        >> "$LOGFILE" 2>&1
    h_count=$(ls "$OUTPUT_DIR/python/$repo/fuzz_targets"/*.py 2>/dev/null | wc -l)
    if [ "$h_count" = "0" ]; then
        echo "  [HARNESS FAIL] 0 generated"
        continue
    fi
    echo "  [HARNESS] $h_count harnesses generated"
    sleep 1

    # Count
    targets_dir="$OUTPUT_DIR/python/$repo/fuzz_targets"
    harness_count=0
    [ -d "$targets_dir" ] && harness_count=$(ls "$targets_dir"/*.py 2>/dev/null | wc -l)
    echo "  [OK] $harness_count harnesses generated"
done

echo "=============================================="
echo "DONE: $(date)"
echo "=============================================="
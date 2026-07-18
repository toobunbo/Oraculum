#!/usr/bin/env bash
# Master experiment script — runs overnight, no questions asked.
# Phase 1: Generate harnesses (oraculum pipeline)
# Phase 2: Baseline smoke test
# Phase 3: Repair (force-apply + normal mode)
# Phase 4: Post-repair smoke test
# Phase 5: Report

ORACULUM_ROOT="/home/trieudai/Oraculum"
OUTPUT_DIR="$ORACULUM_ROOT/output/python"
LOG_DIR="$ORACULUM_ROOT/OR_env/logs"
REPORT_DIR="$ORACULUM_ROOT/OR_env/experiment_reports"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOCKFILE="$LOG_DIR/experiment.lock"

mkdir -p "$LOG_DIR" "$REPORT_DIR" "$OUTPUT_DIR"

# Prevent concurrent runs
if [ -f "$LOCKFILE" ] && kill -0 "$(cat "$LOCKFILE")" 2>/dev/null; then
    echo "Experiment already running (PID $(cat "$LOCKFILE"))"
    exit 1
fi
echo $$ > "$LOCKFILE"

exec > "$LOG_DIR/experiment_master_${TIMESTAMP}.log" 2>&1

echo "=============================================="
echo "MASTER EXPERIMENT — $(date)"
echo "=============================================="
echo ""

cd "$ORACULUM_ROOT"
set -a && source .env && set +a
source .venv/bin/activate

echo "LLM_MODEL=$LLM_MODEL"
echo "OPENAI_API_BASE=$OPENAI_API_BASE"
echo ""

cleanup() {
    rm -f "$LOCKFILE"
}
trap cleanup EXIT

# =============================================
# PHASE 1: Generate harnesses
# =============================================
echo "=============================================="
echo "PHASE 1: Oriculum Pipeline — $(date)"
echo "=============================================="

# Respawning loop: if the pipeline script dies, restart it
PIPELINE_PID=""
MAX_RESTARTS=5
RESTART_COUNT=0

while [ $RESTART_COUNT -lt $MAX_RESTARTS ]; do
    echo "[Respawn $RESTART_COUNT] Starting pipeline at $(date)"
    bash "$ORACULUM_ROOT/OR_env/run_oraculum_pipeline.sh" &
    PIPELINE_PID=$!
    
    # Wait for pipeline to finish
    wait $PIPELINE_PID
    EXIT_CODE=$?
    
    if [ $EXIT_CODE -eq 0 ]; then
        echo "Pipeline completed successfully at $(date)"
        break
    fi
    
    echo "Pipeline exited with code $EXIT_CODE at $(date)"
    
    # Check if any harnesses were generated (if so, we can proceed)
    HARNESS_COUNT=$(find "$OUTPUT_DIR" -name "*.py" -path "*/fuzz_targets/*" 2>/dev/null | wc -l)
    if [ "$HARNESS_COUNT" -gt 0 ]; then
        echo "Got $HARNESS_COUNT harnesses — proceeding to smoke test"
        break
    fi
    
    RESTART_COUNT=$((RESTART_COUNT + 1))
    if [ $RESTART_COUNT -lt $MAX_RESTARTS ]; then
        echo "Waiting 60s before restart..."
        sleep 60
    fi
done

HARNESSES=$(find "$OUTPUT_DIR" -name "*.py" -path "*/fuzz_targets/*" 2>/dev/null | wc -l)
echo "Total harnesses generated: $HARNESSES"
echo ""

if [ "$HARNESSES" -eq 0 ]; then
    echo "FATAL: No harnesses generated after $MAX_RESTARTS attempts"
    exit 1
fi

# =============================================
# PHASE 2: Baseline smoke test
# =============================================
echo "=============================================="
echo "PHASE 2: Baseline Smoke Test — $(date)"
echo "=============================================="

BASELINE_CSV="$REPORT_DIR/baseline_smoke_${TIMESTAMP}.csv"
echo "harness,compile,status,bug,time_ms" > "$BASELINE_CSV"

TOTAL=0
PASS=0
BUG=0
ERR=0

for harness in $(find "$OUTPUT_DIR" -name "*.py" -path "*/fuzz_targets/*" | sort); do
    TOTAL=$((TOTAL + 1))
    fname=$(basename "$harness")
    repo=$(echo "$harness" | sed "s|$OUTPUT_DIR/python/||;s|/fuzz_targets/.*||")
    
    # ast parse check
    ast_ok="N"
    if python3 -c "import ast; ast.parse(open('$harness').read())" 2>/dev/null; then
        ast_ok="Y"
    fi
    
    # Smoke test (1 iteration)
    smoke_start=$(date +%s%N)
    smoke_out=$(timeout 30 python3 "$harness" -runs=1 2>&1)
    exit_code=$?
    smoke_end=$(date +%s%N)
    elapsed=$(( (smoke_end - smoke_start) / 1000000 ))
    
    if echo "$smoke_out" | grep -qiE "RuntimeError:|ValueError:|AssertionError:"; then
        status="BUG"
        bug="Y"
    elif [ "$exit_code" -eq 0 ]; then
        status="PASS"
        bug="N"
    else
        status="ERR"
        bug="N"
    fi
    
    echo "$repo/$fname,$ast_ok,$status,$bug,$elapsed" >> "$BASELINE_CSV"
    
    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        BUG)  BUG=$((BUG + 1)) ;;
        ERR)  ERR=$((ERR + 1)) ;;
    esac
done

echo ""
echo "Baseline results:"
echo "  Total: $TOTAL"
echo "  PASS:  $PASS"
echo "  BUG:   $BUG"
echo "  ERR:   $ERR ($(echo "scale=1; $ERR*100/$TOTAL" | bc)%)"
echo ""

# =============================================
# PHASE 3: Apply repair
# =============================================
echo "=============================================="
echo "PHASE 3: Repair — $(date)"
echo "=============================================="

# Force-apply first
python3 "$ORACULUM_ROOT/scripts/run_repair_loop.py" "$OUTPUT_DIR" --force-apply \
    > "$REPORT_DIR/repair_force_${TIMESTAMP}.txt" 2>&1
echo "Force-apply complete"

# Then normal mode for remaining ERR cases
python3 "$ORACULUM_ROOT/scripts/run_repair_loop.py" "$OUTPUT_DIR" \
    > "$REPORT_DIR/repair_normal_${TIMESTAMP}.txt" 2>&1
echo "Normal-mode repair complete"
echo ""

# =============================================
# PHASE 4: Post-repair smoke test
# =============================================
echo "=============================================="
echo "PHASE 4: Post-Repair Smoke Test — $(date)"
echo "=============================================="

POST_CSV="$REPORT_DIR/post_repair_smoke_${TIMESTAMP}.csv"
echo "harness,compile,status,bug,time_ms" > "$POST_CSV"

POST_PASS=0
POST_BUG=0
POST_ERR=0

for harness in $(find "$OUTPUT_DIR" -name "*.py" -path "*/fuzz_targets/*" | sort); do
    fname=$(basename "$harness")
    repo=$(echo "$harness" | sed "s|$OUTPUT_DIR/python/||;s|/fuzz_targets/.*||")
    
    ast_ok="N"
    python3 -c "import ast; ast.parse(open('$harness').read())" 2>/dev/null && ast_ok="Y"
    
    smoke_start=$(date +%s%N)
    smoke_out=$(timeout 30 python3 "$harness" -runs=1 2>&1)
    exit_code=$?
    smoke_end=$(date +%s%N)
    elapsed=$(( (smoke_end - smoke_start) / 1000000 ))
    
    if echo "$smoke_out" | grep -qiE "RuntimeError:|ValueError:|AssertionError:"; then
        status="BUG"
        bug="Y"
    elif [ "$exit_code" -eq 0 ]; then
        status="PASS"
        bug="N"
    else
        status="ERR"
        bug="N"
    fi
    
    echo "$repo/$fname,$ast_ok,$status,$bug,$elapsed" >> "$POST_CSV"
    
    case "$status" in
        PASS) POST_PASS=$((POST_PASS + 1)) ;;
        BUG)  POST_BUG=$((POST_BUG + 1)) ;;
        ERR)  POST_ERR=$((POST_ERR + 1)) ;;
    esac
done

echo ""
echo "Post-repair results:"
echo "  Total: $TOTAL"
echo "  PASS:  $POST_PASS"
echo "  BUG:   $POST_BUG"
echo "  ERR:   $POST_ERR ($(echo "scale=1; $POST_ERR*100/$TOTAL" | bc)%)"
echo ""

# =============================================
# PHASE 5: Report
# =============================================
echo "=============================================="
echo "PHASE 5: Report — $(date)"
echo "=============================================="

REPORT_FILE="$REPORT_DIR/experiment_report_${TIMESTAMP}.md"

cat > "$REPORT_FILE" << EOF
# Experiment Report — $(date)

## Config
- Model: \`glm-5\`
- API: Z.ai
- Retry: 4 attempts, backoff 8s→16s→32s
- Timeouts: 300s

## Pipeline Results
- Total harnesses generated: **$TOTAL**

## Baseline Smoke Test (before repair)
| Outcome | Count | Percentage |
|---|---|---|
| PASS | $PASS | $(echo "scale=1; $PASS*100/$TOTAL" | bc)% |
| BUG | $BUG | $(echo "scale=1; $BUG*100/$TOTAL" | bc)% |
| ERR | $ERR | $(echo "scale=1; $ERR*100/$TOTAL" | bc)% |

## Post-Repair Smoke Test
| Outcome | Count | Percentage |
|---|---|---|
| PASS | $POST_PASS | $(echo "scale=1; $POST_PASS*100/$TOTAL" | bc)% |
| BUG | $POST_BUG | $(echo "scale=1; $POST_BUG*100/$TOTAL" | bc)% |
| ERR | $POST_ERR | $(echo "scale=1; $POST_ERR*100/$TOTAL" | bc)% |

## Improvement
- ERR reduction: $ERR → $POST_ERR ($(echo "scale=1; ($ERR-$POST_ERR)*100/$ERR" | bc)% relative reduction)

## Academic baseline comparison
| Metric | Academic (original) | This run |
|---|---|---|
| Total harnesses | 104 | $TOTAL |
| Baseline ERR | 66 (63.5%) | $ERR ($(echo "scale=1; $ERR*100/$TOTAL" | bc)%) |
| Post-repair ERR | — | $POST_ERR ($(echo "scale=1; $POST_ERR*100/$TOTAL" | bc)%) |
EOF

cat "$REPORT_FILE"
echo ""
echo "Report saved: $REPORT_FILE"

echo ""
echo "=============================================="
echo "EXPERIMENT COMPLETE — $(date)"
echo "=============================================="
echo "Log: $LOG_DIR/experiment_master_${TIMESTAMP}.log"
echo "Report: $REPORT_FILE"

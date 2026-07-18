#!/usr/bin/env bash
# Batch pipeline for RealVuln 66-repo evaluation
# Usage: ./batch_pipeline.sh [phase]
#   phase 1: VHX scan only
#   phase 2: Generate functions.csv (for repos where VHX context fails)
#   phase 3: Oraculum pipeline (ingest → classify → oracle → harness)
#   phase 4: Smoke test + fuzz
#   (default): all phases sequentially

set -euo pipefail

ORACULUM_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VHX_ROOT="/home/trieudai/VulnHunterX"
REPOS_DIR="$VHX_ROOT/benchmarks/datasets/realvuln/repos"
GT_DIR="$VHX_ROOT/benchmarks/datasets/realvuln/ground-truth"
VHX_OUTPUT="$VHX_ROOT/output/python"
ORACULUM_OUTPUT="$ORACULUM_ROOT/output/python"
# Explicitly set and export LLM_MODEL (overrides .bashrc export)
export LLM_MODEL="qwen3-coder:480b-cloud"
LOG_DIR="$ORACULUM_ROOT/OR_env/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$LOG_DIR"

# Get list of repos that have Python files and ground-truth
get_repos() {
    for gt_file in "$GT_DIR"/*/ground-truth.json; do
        repo=$(basename "$(dirname "$gt_file")")
        repo_path="$REPOS_DIR/$repo"
        py_count=$(find "$repo_path" -name "*.py" -type f 2>/dev/null | wc -l)
        if [ "$py_count" -gt 0 ]; then
            echo "$repo"
        fi
    done | sort
}

PHASE="${1:-all}"

case "$PHASE" in
    1|scan)
        echo "=============================================="
        echo " PHASE 1: VHX Scan — $(date)"
        echo "=============================================="
        
        cd "$VHX_ROOT"
        source .venv/bin/activate
        
        TOTAL_REPOS=$(get_repos | wc -l)
        COUNT=0
        for repo in $(get_repos); do
            COUNT=$((COUNT + 1))
            vhx_out="$VHX_OUTPUT/$repo/verification_results"
            
            # Skip if already scanned
            if [ -d "$vhx_out" ] && ls "$vhx_out"/summary_*.json 1>/dev/null 2>&1; then
                tp_count=$(ls "$vhx_out"/*.json 2>/dev/null | grep -v "summary\|report" | wc -l)
                echo "[$COUNT/$TOTAL_REPOS] [SKIP] $repo — already scanned ($tp_count findings)"
                continue
            fi
            
            echo "[$COUNT/$TOTAL_REPOS] [SCAN] $repo — $(date)"
            log_file="$LOG_DIR/vhx_scan_${repo}_${TIMESTAMP}.log"
            
            timeout 1800 vuln-hunter-x scan \
                --local-path "$REPOS_DIR/$repo" \
                --lang python \
                --name "$repo" 2>&1 | tee "$log_file"
            
            exit_code=$?
            if [ $exit_code -ne 0 ]; then
                echo "[$COUNT/$TOTAL_REPOS] [FAIL] $repo — exit code $exit_code"
            else
                tp_count=$(ls "$VHX_OUTPUT/$repo/verification_results"/*.json 2>/dev/null | grep -v "summary\|report" | wc -l)
                echo "[$COUNT/$TOTAL_REPOS] [OK]   $repo — $tp_count TP findings"
            fi
            echo ""
        done
        echo "=== Phase 1 complete: $(date) ==="
        ;;
    
    2|functions)
        echo "=============================================="
        echo " PHASE 2: Generate functions.csv — $(date)"
        echo "=============================================="
        
        cd "$ORACULUM_ROOT"
        python3 OR_env/generate_functions_csv.py
        echo "=== Phase 2 complete: $(date) ==="
        ;;
    
    3|oraculum)
        echo "=============================================="
        echo " PHASE 3: Oraculum Pipeline — $(date)"
        echo "=============================================="
        
        cd "$ORACULUM_ROOT"
        source .venv/bin/activate
        
        TOTAL_REPOS=$(get_repos | wc -l)
        COUNT=0
        for repo in $(get_repos); do
            COUNT=$((COUNT + 1))
            vhx_out="$VHX_OUTPUT/$repo/verification_results"
            targets_dir="$ORACULUM_OUTPUT/$repo/fuzz_targets"
            
            # Skip if no VHX results
            if [ ! -d "$vhx_out" ]; then
                echo "[$COUNT/$TOTAL_REPOS] [SKIP] $repo — no VHX results yet"
                continue
            fi
            
            tp_count=$(ls "$vhx_out"/*.json 2>/dev/null | grep -v "summary\|report" | wc -l)
            if [ "$tp_count" -eq 0 ]; then
                echo "[$COUNT/$TOTAL_REPOS] [SKIP] $repo — 0 TP findings"
                continue
            fi
            
            # Skip if already has harnesses
            harness_count=$(ls "$targets_dir"/*.py 2>/dev/null | wc -l)
            if [ "$harness_count" -gt 0 ]; then
                echo "[$COUNT/$TOTAL_REPOS] [SKIP] $repo — already has $harness_count harnesses"
                continue
            fi
            
            echo "[$COUNT/$TOTAL_REPOS] [INGEST] $repo ($tp_count TP findings) — $(date)"
            log_file="$LOG_DIR/oraculum_ingest_${repo}_${TIMESTAMP}.log"
            oraculum ingest \
                --vhx-root "$VHX_ROOT" \
                --repo "$repo" \
                --output-dir "$ORACULUM_OUTPUT" \
                --force 2>&1 | tee "$log_file" || echo "  [WARN] ingest for $repo had issues"
            
            echo "[$COUNT/$TOTAL_REPOS] [CLASSIFY] $repo — $(date)"
            log_file="$LOG_DIR/oraculum_classify_${repo}_${TIMESTAMP}.log"
            oraculum classify \
                --repo "$repo" \
                --output-dir "$ORACULUM_OUTPUT" \
                --force 2>&1 | tee "$log_file" || echo "  [WARN] classify for $repo had issues"
            
            echo "[$COUNT/$TOTAL_REPOS] [ORACLE] $repo — $(date)"
            log_file="$LOG_DIR/oraculum_oracle_${repo}_${TIMESTAMP}.log"
            oraculum oracle \
                --repo "$repo" \
                --output-dir "$ORACULUM_OUTPUT" \
                --force 2>&1 | tee "$log_file" || echo "  [WARN] oracle for $repo had issues"
            
            echo "[$COUNT/$TOTAL_REPOS] [HARNESS] $repo — $(date)"
            log_file="$LOG_DIR/oraculum_harness_${repo}_${TIMESTAMP}.log"
            oraculum harness \
                --repo "$repo" \
                --output-dir "$ORACULUM_OUTPUT" \
                --force 2>&1 | tee "$log_file" || echo "  [WARN] harness for $repo had issues"
            
            harness_count=$(ls "$targets_dir"/*.py 2>/dev/null | wc -l)
            echo "[$COUNT/$TOTAL_REPOS] [OK] $repo — $harness_count harnesses generated"
            echo ""
        done
        echo "=== Phase 3 complete: $(date) ==="
        ;;
    
    4|smoke)
        echo "=============================================="
        echo " PHASE 4: Smoke Tests — $(date)"
        echo "=============================================="
        
        cd "$ORACULUM_ROOT"
        source .venv/bin/activate
        
        RESULTS_FILE="$LOG_DIR/smoke_results_${TIMESTAMP}.csv"
        echo "repo,finding_id,compile,smoke,crash,time_ms" > "$RESULTS_FILE"
        
        TOTAL_HARNESSES=0
        for repo in $(get_repos); do
            targets_dir="$ORACULUM_OUTPUT/$repo/fuzz_targets"
            [ -d "$targets_dir" ] || continue
            for harness in "$targets_dir"/*.py; do
                [ -f "$harness" ] || continue
                TOTAL_HARNESSES=$((TOTAL_HARNESSES + 1))
            done
        done
        
        COUNT=0
        for repo in $(get_repos); do
            targets_dir="$ORACULUM_OUTPUT/$repo/fuzz_targets"
            [ -d "$targets_dir" ] || continue
            
            for harness in "$targets_dir"/*.py; do
                [ -f "$harness" ] || continue
                COUNT=$((COUNT + 1))
                finding_id=$(basename "$harness" .py)
                
                echo "[$COUNT/$TOTAL_HARNESSES] [SMOKE] $repo / $finding_id"
                
                compile_status="N"
                smoke_status="FAIL"
                crash="N"
                elapsed=0
                
                # Compile test
                start=$(date +%s%N 2>/dev/null || echo 0)
                compile_output=$(python3 -c "
import sys, ast
try:
    with open('$harness') as f:
        code = f.read()
    ast.parse(code)
    print('COMPILE_OK')
except SyntaxError as e:
    print(f'COMPILE_FAIL: {e}')
" 2>&1)
                if echo "$compile_output" | grep -q "COMPILE_OK"; then
                    compile_status="Y"
                fi
                
                # Smoke test (1 iter)
                if [ "$compile_status" = "Y" ]; then
                    smoke_output=$(timeout 30 .venv/bin/python "$harness" -runs=1 2>&1)
                    exit_code=$?
                else
                    smoke_output=""
                    exit_code=1
                fi
                end=$(date +%s%N 2>/dev/null || echo 0)
                if [ "$end" -gt "$start" ] 2>/dev/null; then
                    elapsed=$(( (end - start) / 1000000 ))
                fi
                
                if echo "$smoke_output" | grep -qi "RuntimeError\|CRASH\|ERROR:"; then
                    smoke_status="CRASH"
                    crash="Y"
                elif [ "$exit_code" -eq 0 ]; then
                    smoke_status="PASS"
                fi
                
                echo "$repo,$finding_id,$compile_status,$smoke_status,$crash,$elapsed" >> "$RESULTS_FILE"
                echo "  → compile=$compile_status smoke=$smoke_status crash=$crash ${elapsed}ms"
            done
        done
        
        echo ""
        echo "=== Smoke Test Summary ==="
        total=$(tail -n+2 "$RESULTS_FILE" | wc -l)
        compiled=$(grep ",Y," "$RESULTS_FILE" 2>/dev/null | wc -l)
        crashed=$(grep ",Y$" "$RESULTS_FILE" 2>/dev/null | wc -l)
        passed=$(grep "PASS" "$RESULTS_FILE" 2>/dev/null | wc -l)
        echo "Total harnesses: $total"
        echo "Compiled:        $compiled"
        echo "Smoke PASS:      $passed"
        echo "Crashed (bug!):  $crashed"
        echo "Results: $RESULTS_FILE"
        echo "=== Phase 4 complete: $(date) ==="
        ;;
    
    5|fuzz)
        echo "=============================================="
        echo " PHASE 5: Real Fuzzing — $(date)"
        echo "=============================================="
        
        cd "$ORACULUM_ROOT"
        source .venv/bin/activate
        
        FUZZ_RESULTS="$LOG_DIR/fuzz_results_${TIMESTAMP}.csv"
        echo "repo,finding_id,iterations,bug_detected,time_seconds" > "$FUZZ_RESULTS"
        
        for repo in $(get_repos); do
            targets_dir="$ORACULUM_OUTPUT/$repo/fuzz_targets"
            [ -d "$targets_dir" ] || continue
            
            for harness in "$targets_dir"/*.py; do
                [ -f "$harness" ] || continue
                finding_id=$(basename "$harness" .py)
                
                echo "[FUZZ] $repo / $finding_id — 100K iterations"
                start=$(date +%s)
                fuzz_output=$(timeout 60 .venv/bin/python "$harness" -runs=100000 2>&1)
                end=$(date +%s)
                elapsed=$((end - start))
                
                if echo "$fuzz_output" | grep -qi "RuntimeError\|CRASH\|ERROR:"; then
                    bug_detected="Y"
                else
                    bug_detected="N"
                fi
                
                echo "$repo,$finding_id,100000,$bug_detected,$elapsed" >> "$FUZZ_RESULTS"
                echo "  → bug=$bug_detected ${elapsed}s"
            done
        done
        
        echo ""
        echo "=== Fuzzing Summary ==="
        total=$(tail -n+2 "$FUZZ_RESULTS" | wc -l)
        bugs=$(grep ",Y," "$FUZZ_RESULTS" 2>/dev/null | wc -l)
        echo "Total fuzzed: $total"
        echo "Bugs detected: $bugs"
        echo "Results: $FUZZ_RESULTS"
        echo "=== Phase 5 complete: $(date) ==="
        ;;
    
    all|*)
        echo "=============================================="
        echo " FULL PIPELINE START — $(date)"
        echo "=============================================="
        TOTAL_REPOS=$(get_repos | wc -l)
        echo "Repos to process: $TOTAL_REPOS"
        echo ""
        
        bash "$0" 1
        bash "$0" 2
        bash "$0" 3
        bash "$0" 4
        bash "$0" 5
        echo "=============================================="
        echo " FULL PIPELINE COMPLETE — $(date)"
        echo "=============================================="
        ;;
esac

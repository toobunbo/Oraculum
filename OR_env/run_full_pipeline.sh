#!/usr/bin/env bash
# Full Oraculum pipeline — chạy AFK qua đêm
set -euo pipefail

ORACULUM_ROOT="/home/trieudai/Oraculum"
LOG_DIR="$ORACULUM_ROOT/OR_env/logs"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)

mkdir -p "$LOG_DIR"

# Force correct env (override .bashrc)
unset LLM_MODEL
export LLM_PROVIDER=openai
export LLM_MODEL=glm-5-turbo
export OPENAI_API_KEY=bbda4cc5707343afb70b6f5d9d1074b2.4K6fTLBvZKh17KeP
export OPENAI_BASE_URL=https://api.z.ai/api/coding/paas/v4

cd "$ORACULUM_ROOT"
source .venv/bin/activate

# B1: Generate functions.csv cho repos còn thiếu
echo "[1/4] Generating functions.csv ..."
python3 OR_env/generate_functions_csv.py 2>&1 | tee "$LOG_DIR/functions_csv_$TIMESTAMP.log"

# B2: Ingest tất cả repos
echo "[2/4] Ingesting all repos ..."
INGEST_LOG="$LOG_DIR/ingest_$TIMESTAMP.log"
echo "repo,selected,enriched,skipped,failed" > "$INGEST_LOG"

for d in /home/trieudai/VulnHunterX/output/python/*/verification_results/; do
    repo=$(basename "$(dirname "$d")")
    tp=$(ls "$d"/*.json 2>/dev/null | grep -cv "summary\|report" || true)
    [ "$tp" -eq 0 ] && continue
    
    echo "  ingest $repo ($tp findings)"
    output=$(timeout 60 oraculum ingest \
        --vhx-root /home/trieudai/VulnHunterX \
        --repo "$repo" \
        --output-dir output \
        --force 2>&1 | tail -3) || true
    
    selected=$(echo "$output" | grep -oP 'selected=\K\d+' || echo 0)
    enriched=$(echo "$output" | grep -oP 'enriched=\K\d+' || echo 0)
    skipped=$(echo "$output" | grep -oP 'skipped=\K\d+' || echo 0)
    failed=$(echo "$output" | grep -oP 'failed=\K\d+' || echo 0)
    echo "$repo,$selected,$enriched,$skipped,$failed" >> "$INGEST_LOG"
done

# B3: Classify tất cả repos
echo "[3/4] Classifying all repos ..."
CLASSIFY_LOG="$LOG_DIR/classify_$TIMESTAMP.log"
echo "repo,total,generated,skipped,failed" > "$CLASSIFY_LOG"

while IFS=',' read -r repo selected enriched skipped failed; do
    [ "$enriched" -eq 0 ] && continue
    echo "  classify $repo ($enriched findings)"
    output=$(timeout 300 oraculum classify \
        --repo "$repo" \
        --output-dir output \
        --force 2>&1 | tail -3) || true
    gen=$(echo "$output" | grep -oP 'generated=\K\d+' || echo 0)
    skp=$(echo "$output" | grep -oP 'skipped=\K\d+' || echo 0)
    fail=$(echo "$output" | grep -oP 'failed=\K\d+' || echo 0)
    echo "$repo,$enriched,$gen,$skp,$fail" >> "$CLASSIFY_LOG"
done < <(tail -n+2 "$INGEST_LOG")

# B4: Oracle tất cả repos
echo "[4/4] Generating oracles ..."
ORACLE_LOG="$LOG_DIR/oracle_$TIMESTAMP.log"
echo "repo,total,generated,skipped,failed" > "$ORACLE_LOG"

while IFS=',' read -r repo total gen skp fail; do
    [ "$gen" -eq 0 ] && continue
    echo "  oracle $repo ($gen findings)"
    output=$(timeout 600 oraculum oracle \
        --repo "$repo" \
        --output-dir output \
        --force 2>&1 | tail -3) || true
    gen2=$(echo "$output" | grep -oP 'generated=\K\d+' || echo 0)
    skp2=$(echo "$output" | grep -oP 'skipped=\K\d+' || echo 0)
    fail2=$(echo "$output" | grep -oP 'failed=\K\d+' || echo 0)
    echo "$repo,$gen,$gen2,$skp2,$fail2" >> "$ORACLE_LOG"
done < <(tail -n+2 "$CLASSIFY_LOG")

# B5: Harness tất cả repos
echo "[5/5] Generating harnesses ..."
HARNESS_LOG="$LOG_DIR/harness_$TIMESTAMP.log"
echo "repo,total,generated,skipped,failed" > "$HARNESS_LOG"

while IFS=',' read -r repo total gen skp fail; do
    [ "$gen" -eq 0 ] && continue
    echo "  harness $repo ($gen oracles)"
    output=$(timeout 600 oraculum harness \
        --repo "$repo" \
        --output-dir output \
        --force 2>&1 | tail -3) || true
    gen2=$(echo "$output" | grep -oP 'generated=\K\d+' || echo 0)
    skp2=$(echo "$output" | grep -oP 'skipped=\K\d+' || echo 0)
    fail2=$(echo "$output" | grep -oP 'failed=\K\d+' || echo 0)
    echo "$repo,$gen,$gen2,$skp2,$fail2" >> "$HARNESS_LOG"
done < <(tail -n+2 "$ORACLE_LOG")

# B6: Smoke test tất cả harnesses
echo "[6/6] Smoke testing ..."
SMOKE_LOG="$LOG_DIR/smoke_$TIMESTAMP.log"
echo "repo,finding_id,compile,smoke" > "$SMOKE_LOG"

for repo_dir in "$ORACULUM_ROOT"/output/python/*/fuzz_targets/; do
    [ -d "$repo_dir" ] || continue
    repo=$(basename "$(dirname "$repo_dir")")
    for harness in "$repo_dir"/*.py; do
        [ -f "$harness" ] || continue
        finding=$(basename "$harness" .py)
        
        compile="Y"
        smoke="FAIL"
        
        # Compile check
        python3 -c "import ast; ast.parse(open('$harness').read())" 2>/dev/null || compile="N"
        
        # Smoke (1 iter)
        if [ "$compile" = "Y" ]; then
            out=$(timeout 30 .venv/bin/python "$harness" -runs=1 2>&1) || true
            if echo "$out" | grep -qi "RuntimeError\|CRASH\|ERROR:"; then
                smoke="CRASH"
            elif [ $? -eq 0 ]; then
                smoke="PASS"
            fi
        fi
        
        echo "$repo,$finding,$compile,$smoke" >> "$SMOKE_LOG"
    done
done

# B7: Tổng kết
echo ""
echo "=============================================="
echo " SUMMARY — $(date)"
echo "=============================================="
echo ""
echo "Ingest:    $(tail -n+2 "$INGEST_LOG" | wc -l) repos"
echo "Classify:  $(tail -n+2 "$CLASSIFY_LOG" | grep -v ",0,0,0" | wc -l) repos"
echo "Oracle:    $(tail -n+2 "$ORACLE_LOG" | grep -v ",0,0,0" | wc -l) repos"
echo "Harness:   $(tail -n+2 "$HARNESS_LOG" | grep -v ",0,0,0" | wc -l) repos"
echo "Smoke:     $(tail -n+2 "$SMOKE_LOG" | wc -l) harnesses"
echo ""
echo "Compiled:  $(grep ",Y," "$SMOKE_LOG" | wc -l)"
echo "Pass:      $(grep "PASS" "$SMOKE_LOG" | wc -l)"
echo "Crash:     $(grep "CRASH" "$SMOKE_LOG" | wc -l)"
echo ""
echo "Logs: $LOG_DIR/"
echo "=============================================="

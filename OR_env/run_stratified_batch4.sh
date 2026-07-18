#!/usr/bin/env bash
# Batch4 — Re-run 6 repos that failed due to API overload (ServiceUnavailableError)
set -uo pipefail

ORACULUM_ROOT="/home/trieudai/Oraculum"
VHX_ROOT="/home/trieudai/VulnHunterX"
OUTPUT_DIR="$ORACULUM_ROOT/output/python"
LOG_DIR="$ORACULUM_ROOT/OR_env/logs"
START_TIME=$(date +%Y%m%d_%H%M%S)

mkdir -p "$LOG_DIR"
cd "$ORACULUM_ROOT"
set -a && source .env && set +a
source .venv/bin/activate

REPOS=(
  "vc-codex-high-seeded-v2-fintech-lending-fastapi"
  "vc-claude-code-seeded-v2-healthcare-clinic-django"
  "realvuln-vulnpy"
  "realvuln-flask-xss"
  "realvuln-vfapi"
  "realvuln-vulnerable-python-apps"
)

TOTAL=${#REPOS[@]}
COUNT=0
COMPLETED=0

for repo in "${REPOS[@]}"; do
  COUNT=$((COUNT + 1))
  LOGFILE="$LOG_DIR/batch4_${repo}_${START_TIME}.log"
  echo "[$COUNT/$TOTAL] ===== $repo =====" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"

  echo "  [INGEST] $(date)" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"
  timeout 300 oraculum ingest --vhx-root "$VHX_ROOT" --repo "$repo" --output-dir "$OUTPUT_DIR" --force >> "$LOGFILE" 2>&1
  i_sel=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/verification_results/summary.json')); print(d.get('counts',{}).get('enriched',0))" 2>/dev/null || echo 0)
  [ "$i_sel" = "0" ] && { echo "  [SKIP] 0 enriched"; continue; }
  echo "  [INGEST] $i_sel findings" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"

  echo "  [CLASSIFY] $(date)" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"
  timeout 1800 oraculum classify --repo "$repo" --output-dir "$OUTPUT_DIR" --force >> "$LOGFILE" 2>&1
  c_gen=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/classifications/status.json')); print(d.get('counts',{}).get('generated',0))" 2>/dev/null || echo 0)
  c_fail=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/classifications/status.json')); print(d.get('counts',{}).get('failed',0))" 2>/dev/null || echo 0)
  c_sel=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/classifications/status.json')); print(d.get('counts',{}).get('selected',0))" 2>/dev/null || echo 0)
  [ "$c_gen" = "0" ] && { echo "  [CLASSIFY FAIL] 0/$c_sel generated ($c_fail failed)" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"; continue; }
  echo "  [CLASSIFY] $c_gen/$c_sel ($c_fail failed)" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"

  echo "  [ORACLE] $(date)" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"
  timeout 1800 oraculum oracle --repo "$repo" --output-dir "$OUTPUT_DIR" --force >> "$LOGFILE" 2>&1
  o_gen=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/fuzz_oracles/status.json')); print(d.get('counts',{}).get('generated',0))" 2>/dev/null || echo 0)
  o_fail=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/fuzz_oracles/status.json')); print(d.get('counts',{}).get('failed',0))" 2>/dev/null || echo 0)
  [ "$o_gen" = "0" ] && { echo "  [ORACLE FAIL] 0 generated" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"; continue; }
  echo "  [ORACLE] $o_gen generated ($o_fail failed)" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"

  echo "  [HARNESS] $(date)" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"
  timeout 1800 oraculum harness --repo "$repo" --output-dir "$OUTPUT_DIR" >> "$LOGFILE" 2>&1
  h_count=$(ls "$OUTPUT_DIR/python/$repo/fuzz_targets"/*.py 2>/dev/null | wc -l)
  [ "$h_count" = "0" ] && { echo "  [HARNESS FAIL] 0 generated" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"; continue; }
  echo "  [HARNESS] $h_count harnesses" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"
  COMPLETED=$((COMPLETED + 1))
  echo "  [OK] $repo ($h_count harnesses)" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"
  echo "" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"
done

echo "DONE: $(date) | Completed: $COMPLETED/$TOTAL" | tee -a "$LOG_DIR/batch4_master_${START_TIME}.log"

#!/usr/bin/env bash
# Stratified sample: 4 repos for thesis evaluation
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
  "realvuln-vulpy"
  "vc-claude-code-seeded-v2-fintech-lending-fastapi"
  "vc-codex-high-seeded-v2-logistics-dispatch-fastapi"
  "vc-kimi-code-seeded-v2-hr-payroll-django"
)

TOTAL=${#REPOS[@]}
COUNT=0

for repo in "${REPOS[@]}"; do
  COUNT=$((COUNT + 1))
  LOGFILE="$LOG_DIR/sample_${repo}_${START_TIME}.log"
  echo "[$COUNT/$TOTAL] ===== $repo =====" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"

  echo "  [INGEST] $(date)" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
  timeout 300 oraculum ingest --vhx-root "$VHX_ROOT" --repo "$repo" --output-dir "$OUTPUT_DIR" --force >> "$LOGFILE" 2>&1
  if [ $? -ne 0 ]; then
    echo "  [INGEST FAIL] $(date)" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
    continue
  fi

  echo "  [CLASSIFY] $(date)" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
  timeout 1800 oraculum classify --repo "$repo" --output-dir "$OUTPUT_DIR" --force >> "$LOGFILE" 2>&1
  c_gen=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/classifications/status.json')); print(d.get('counts',{}).get('generated',0))" 2>/dev/null || echo 0)
  c_fail=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/classifications/status.json')); print(d.get('counts',{}).get('failed',0))" 2>/dev/null || echo 0)
  if [ "$c_gen" = "0" ]; then
    echo "  [CLASSIFY FAIL] 0 generated" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
    continue
  fi
  echo "  [CLASSIFY] $c_gen generated ($c_fail failed)" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"

  echo "  [ORACLE] $(date)" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
  timeout 1800 oraculum oracle --repo "$repo" --output-dir "$OUTPUT_DIR" --force >> "$LOGFILE" 2>&1
  o_gen=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/fuzz_oracles/status.json')); print(d.get('counts',{}).get('generated',0))" 2>/dev/null || echo 0)
  o_fail=$(python3 -c "import json; d=json.load(open('$OUTPUT_DIR/python/$repo/fuzz_oracles/status.json')); print(d.get('counts',{}).get('failed',0))" 2>/dev/null || echo 0)
  if [ "$o_gen" = "0" ]; then
    echo "  [ORACLE FAIL] 0 generated" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
    continue
  fi
  echo "  [ORACLE] $o_gen generated ($o_fail failed)" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"

  echo "  [HARNESS] $(date)" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
  timeout 1800 oraculum harness --repo "$repo" --output-dir "$OUTPUT_DIR" >> "$LOGFILE" 2>&1
  h_count=$(ls "$OUTPUT_DIR/python/$repo/fuzz_targets"/*.py 2>/dev/null | wc -l)
  if [ "$h_count" = "0" ]; then
    echo "  [HARNESS FAIL] 0 generated" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
    continue
  fi
  echo "  [HARNESS] $h_count harnesses generated" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
  echo "  [OK] $repo done" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
  echo "" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
done

echo "==============================================" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
echo "DONE: $(date)" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"
echo "==============================================" | tee -a "$LOG_DIR/sample_master_${START_TIME}.log"

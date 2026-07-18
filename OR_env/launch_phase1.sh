#!/usr/bin/env bash
LOGDIR="/home/trieudai/Oraculum/OR_env/logs"
mkdir -p "$LOGDIR"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
nohup bash /home/trieudai/Oraculum/OR_env/batch_pipeline.sh 1 > "$LOGDIR/phase1_scan_${TIMESTAMP}.log" 2>&1 &
echo "Phase 1 launched at $(date), PID: $!"
echo "Log: $LOGDIR/phase1_scan_${TIMESTAMP}.log"

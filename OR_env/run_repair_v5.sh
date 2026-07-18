#!/usr/bin/env bash
set -uo pipefail
cd /home/trieudai/Oraculum
set -a && source .env && set +a
source .venv/bin/activate

python3 << 'PYEOF'
import sys, os, json, glob, time
from collections import Counter

sys.path.insert(0, '/home/trieudai/Oraculum/src')
from oraculum.harness.repair.runner import RepairLoop
from oraculum.harness.repair.dry_run import dry_run_harness

harnesses = sorted(glob.glob('/home/trieudai/Oraculum/output/python/python/*/fuzz_targets/*.py'))
harnesses = [f for f in harnesses if not f.endswith('__init__.py') and f.split('/')[-1] != 'status.json']
total = len(harnesses)
out = '/home/trieudai/Oraculum/OR_env/logs/repair_v5_results.json'
log = '/home/trieudai/Oraculum/OR_env/logs/repair_v5_progress.log'
TO = 45

results = []
start = time.time()

for i, f in enumerate(harnesses, 1):
    open(log, 'a').write(f'[{i}/{total}] {os.path.basename(f)}\n')
    
    # Stage 1: smoke test
    try:
        import subprocess
        proc = subprocess.run([sys.executable, f, '-runs=1'], capture_output=True, text=True, timeout=TO, cwd=os.path.dirname(f))
        stderr = proc.stderr
        if proc.returncode == 0:
            results.append({'file': f, 'status': 'PASS', 'stage': 'smoke'})
            continue
        elif 'RuntimeError:' in stderr or 'AssertionError:' in stderr:
            results.append({'file': f, 'status': 'BUG', 'stage': 'smoke'})
            continue
        
        # Stage 2: Repair Loop
        open(log, 'a').write(f'  -> REPAIR...\n')
        loop = RepairLoop(timeout=TO)
        result = loop.repair_one(f)
        
        if result.final_status == 'PASS':
            results.append({'file': f, 'status': 'PASS', 'stage': 'repaired', 'fixes': result.fixes_applied})
        elif result.final_status == 'BUG':
            results.append({'file': f, 'status': 'BUG', 'stage': 'repaired', 'fixes': result.fixes_applied})
        else:
            # Still failed — get final error type
            err_type = result.final_type.value if result.final_type else 'unknown'
            results.append({'file': f, 'status': 'FAIL', 'stage': 'repaired', 'error': err_type, 'fixes': result.fixes_applied})
    except subprocess.TimeoutExpired:
        results.append({'file': f, 'status': 'TIMEOUT', 'stage': 'smoke'})
    
    if i % 20 == 0:
        json.dump(results, open(out, 'w'), indent=2)

elapsed = time.time() - start
c = Counter(r['status'] for r in results)
repaired = sum(1 for r in results if r.get('stage') == 'repaired' and r['status'] == 'PASS')

print(f'\nTime: {elapsed/60:.1f} min')
print(f'Harnesses: {total}')
for s in ['PASS', 'BUG', 'FAIL', 'TIMEOUT']:
    n = c.get(s, 0)
    if n: print(f'  {s:15s} {n:4d} ({100*n/total:.1f}%)')
print(f'\nRepaired by RepairLoop: {repaired}')
print(f'Total Working: {c.get("PASS",0)+c.get("BUG",0)}/{total} = {100*(c.get("PASS",0)+c.get("BUG",0))/total:.1f}%')

json.dump(results, open(out, 'w'), indent=2)
print(f'Saved: {out}')
PYEOF
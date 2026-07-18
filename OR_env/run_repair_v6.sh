#!/usr/bin/env bash
# === Unset old env vars to prevent credit leak ===
unset LLM_MODEL LLM_PROVIDER OPENAI_API_KEY OPENAI_API_BASE OPENAI_BASE_URL
set -uo pipefail
cd /home/trieudai/Oraculum
set -a && source .env && set +a
source .venv/bin/activate

# Verify we're using the right API
echo "LLM_MODEL=$LLM_MODEL"
echo "OPENAI_API_BASE=$OPENAI_API_BASE"
if echo "$OPENAI_API_BASE" | grep -q "z.ai"; then
    echo "ERROR: Still using Z.ai! Aborting."; exit 1
fi

python3 << 'PYEOF'
import sys, os, json, glob, time, logging
logging.basicConfig(level=logging.WARNING)
sys.path.insert(0, '/home/trieudai/Oraculum/src')

from oraculum.harness.repair.runner import RepairLoop
from collections import Counter

harnesses = sorted(glob.glob('/home/trieudai/Oraculum/output/python/python/*/fuzz_targets/*.py'))
harnesses = [f for f in harnesses if not f.endswith('__init__.py') and f.split('/')[-1] != 'status.json']
total = len(harnesses)
out = '/home/trieudai/Oraculum/OR_env/logs/repair_v6_results.json'
log = '/home/trieudai/Oraculum/OR_env/logs/repair_v6_progress.log'

results = []
start = time.time()

for i, f in enumerate(harnesses, 1):
    name = os.path.basename(f)
    open(log, 'a').write(f'[{i}/{total}] {name}\n')
    
    loop = RepairLoop(timeout=45)
    result = loop.repair_one(f)
    
    entry = {'file': f}
    if result.fixes_applied: entry['fixes'] = result.fixes_applied
    if result.iterations: entry['iterations'] = result.iterations
    
    if result.final_status in ('PASS', 'BUG'):
        entry['status'] = result.final_status
    elif result.initial_status in ('PASS', 'BUG'):
        entry['status'] = result.initial_status
    else:
        entry['status'] = 'FAIL'
        entry['error_type'] = (result.final_type or result.initial_type or '?').value if hasattr((result.final_type or result.initial_type or '?'), 'value') else '?'
    
    results.append(entry)
    
    if i % 20 == 0:
        json.dump(results, open(out, 'w'), indent=2)

elapsed = time.time() - start
c = Counter(r['status'] for r in results)
repaired = sum(1 for r in results if r.get('fixes') and r['status'] == 'PASS')

print(f'\nTime: {elapsed/60:.1f} min')
print(f'Harnesses: {total}')
for s in ['PASS', 'BUG', 'FAIL']:
    n = c.get(s, 0)
    if n: print(f'  {s:15s} {n:4d} ({100*n/total:.1f}%)')
print(f'\nRepaired by RepairLoop: {repaired}')
print(f'Total Working: {c.get("PASS",0)+c.get("BUG",0)}/{total} = {100*(c.get("PASS",0)+c.get("BUG",0))/total:.1f}%')

try:
    v5 = json.load(open('/home/trieudai/Oraculum/OR_env/logs/repair_v5_results.json'))
    v5c = Counter(r['status'] for r in v5)
    v6c = Counter(r['status'] for r in results)
    print(f'\nSo sánh V5 (static) → V6 (LLM Agent):')
    for s in ['PASS', 'BUG', 'FAIL']:
        delta = v6c.get(s,0) - v5c.get(s,0)
        if delta: print(f'  {s}: {v5c.get(s,0)} → {v6c.get(s,0)} ({delta:+d})')
except: pass

json.dump(results, open(out, 'w'), indent=2)
print(f'Saved: {out}')
PYEOF
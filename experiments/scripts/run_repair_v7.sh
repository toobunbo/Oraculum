#!/usr/bin/env bash
# V7 — Full repair loop with: 
# - cwd=repo_root
# - TIMEOUT fixer (instrument_imports → instrument_all)
# - Markdown fence strip
# - Atheris rc=77 crash detection
unset LLM_MODEL LLM_PROVIDER OPENAI_API_KEY OPENAI_API_BASE OPENAI_BASE_URL
set -uo pipefail
cd /home/trieudai/Oraculum
set -a && source .env && set +a
source .venv/bin/activate
echo "LLM_MODEL=$LLM_MODEL"
echo "OPENAI_API_BASE=$OPENAI_API_BASE"
if echo "$OPENAI_API_BASE" | grep -q "z.ai"; then echo "ERROR: Still using Z.ai! Aborting."; exit 1; fi

python3 << 'PYEOF'
import sys, os, json, glob, time, logging
logging.basicConfig(level=logging.WARNING)
sys.path.insert(0, '/home/trieudai/Oraculum/src')

from oraculum.harness.repair.runner import RepairLoop
from collections import Counter

harnesses = sorted(glob.glob('/home/trieudai/Oraculum/output/python/python/*/fuzz_targets/*.py'))
harnesses = [f for f in harnesses if not f.endswith('__init__.py') and f.split('/')[-1] != 'status.json']
total = len(harnesses)
out = '/home/trieudai/Oraculum/OR_env/logs/repair_v7_results.json'
log = '/home/trieudai/Oraculum/OR_env/logs/repair_v7_progress.log'

# Run with 90s timeout (was 45s)
loop = RepairLoop(timeout=90)
results = []
start = time.time()

for i, f in enumerate(harnesses, 1):
    name = os.path.basename(f)
    open(log, 'a').write(f'[{i}/{total}] {name}\n')
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
        entry['error_type'] = str(result.final_type or result.initial_type or '?')
    results.append(entry)
    
    if i % 20 == 0:
        json.dump(results, open(out, 'w'), indent=2)

elapsed = time.time() - start
c = Counter(r['status'] for r in results)
repaired = sum(1 for r in results if r.get('fixes') and r['status'] == 'PASS')
bug_77 = sum(1 for r in results if r.get('fixes') and r['status'] == 'BUG')

print(f'\nTime: {elapsed/60:.1f} min')
print(f'Harnesses: {total}')
for s in ['PASS', 'BUG', 'FAIL']:
    n = c.get(s, 0)
    if n: print(f'  {s:15s} {n:4d} ({100*n/total:.1f}%)')
print(f'\nFixed: {repaired} | Bugs found (Atheris rc=77): {bug_77}')
print(f'Total Working: {c.get("PASS",0)+c.get("BUG",0)}/{total} = {100*(c.get("PASS",0)+c.get("BUG",0))/total:.1f}%')

json.dump(results, open(out, 'w'), indent=2)
print(f'Saved: {out}')
PYEOF
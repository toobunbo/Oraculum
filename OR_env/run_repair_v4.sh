#!/usr/bin/env bash
set -uo pipefail
cd /home/trieudai/Oraculum
set -a && source .env && set +a
source .venv/bin/activate

python3 << 'PYEOF'
import subprocess, sys, json, glob, os, re, time
from collections import Counter

start = time.time()
harnesses = sorted(glob.glob('/home/trieudai/Oraculum/output/python/python/*/fuzz_targets/*.py'))
harnesses = [f for f in harnesses if not f.endswith('__init__.py') and f.split('/')[-1] != 'status.json']
total = len(harnesses)
results = []
TO = 45
out = '/home/trieudai/Oraculum/OR_env/logs/repair_v4_results.json'
log = '/home/trieudai/Oraculum/OR_env/logs/repair_v4_progress.log'

for i, f in enumerate(harnesses, 1):
    repo = f.split('/')[-3]
    name = os.path.basename(f)
    open(log, 'a').write(f'[{i}/{total}] {repo}/{name}\n')
    
    try:
        t0 = time.time()
        proc = subprocess.run(
            [sys.executable, f, '-runs=1'],
            capture_output=True, text=True, timeout=TO,
            cwd=os.path.dirname(f)
        )
        stderr = proc.stderr
        if proc.returncode == 0:
            results.append({'file': f, 'status': 'PASS'})
        elif 'RuntimeError:' in stderr or 'AssertionError:' in stderr:
            results.append({'file': f, 'status': 'BUG'})
        elif 'ModuleNotFoundError' in stderr or 'ImportError' in stderr:
            mod = ''
            for line in stderr.split('\n'):
                if 'ModuleNotFoundError' in line:
                    m = re.search(r"'([^']+)'", line)
                    if m: mod = m.group(1); break
            results.append({'file': f, 'status': 'IMPORT_ERR', 'detail': mod})
        elif proc.returncode == -11:
            results.append({'file': f, 'status': 'SEGFAULT'})
        else:
            results.append({'file': f, 'status': 'OTHER'})
    except subprocess.TimeoutExpired:
        results.append({'file': f, 'status': 'TIMEOUT'})
    
    if i % 20 == 0:
        json.dump(results, open(out, 'w'), indent=2)

elapsed = time.time() - start
c = Counter(r['status'] for r in results)

print(f'\nTime: {elapsed/60:.1f} min')
print(f'Harnesses: {total}')
for s in ['PASS', 'BUG', 'IMPORT_ERR', 'TIMEOUT', 'SEGFAULT', 'OTHER']:
    n = c.get(s, 0)
    if n: print(f'  {s:15s} {n:4d} ({100*n/total:.1f}%)')
print(f'Working: {c.get("PASS",0)+c.get("BUG",0)}/{total} = {100*(c.get("PASS",0)+c.get("BUG",0))/total:.1f}%')

json.dump(results, open(out, 'w'), indent=2)
print(f'Saved: {out}')

for label, path in [('V1 (10s)', 'repair_overnight_results.json'), ('V2 (wrong pip)', 'repair_final_results.json'), ('V3 (partial uv)', 'repair_v3_results.json')]:
    try:
        prev = json.load(open(f'/home/trieudai/Oraculum/OR_env/logs/{path}'))
        prev_c = Counter(r['status'] for r in prev)
        print(f'\nSo sánh với {label}:')
        for s in ['PASS', 'BUG', 'IMPORT_ERR', 'TIMEOUT', 'OTHER']:
            old = prev_c.get(s, 0); new = c.get(s, 0)
            if new != old: print(f'  {s:15s}: {old:3d} → {new:3d} ({new-old:+d})')
    except: pass
PYEOF
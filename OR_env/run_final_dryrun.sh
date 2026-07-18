#!/usr/bin/env bash
set -uo pipefail
cd /home/trieudai/Oraculum
set -a && source .env && set +a
source .venv/bin/activate

python3 << 'PYEOF'
import subprocess, sys, json, glob, os, time
from collections import Counter

harnesses = sorted(glob.glob('/home/trieudai/Oraculum/output/python/python/*/fuzz_targets/*.py'))
harnesses = [f for f in harnesses if not f.endswith('__init__.py') and f.split('/')[-1] != 'status.json']
total = len(harnesses)
out = '/home/trieudai/Oraculum/OR_env/logs/final_results.json'
results = []
start = time.time()

for i, f in enumerate(harnesses, 1):
    repo = f.split('/')[-3]
    cwd = os.path.dirname(f)
    for base in ['/home/trieudai/VulnHunterX/repos/python', '/home/trieudai/VulnHunterX/benchmarks/datasets/realvuln/repos']:
        c = f'{base}/{repo}'
        if os.path.isdir(c): cwd = c; break
    
    sys.stderr.write(f'\r{i}/{total}... ')
    sys.stderr.flush()
    try:
        proc = subprocess.run([sys.executable, f, '-runs=1'], capture_output=True, text=True, timeout=30, cwd=cwd)
        if proc.returncode == 0:
            results.append({'file': f, 'status': 'PASS'})
        elif proc.returncode == 77 or 'RuntimeError:' in proc.stderr or 'AssertionError:' in proc.stderr:
            results.append({'file': f, 'status': 'BUG'})
        else:
            results.append({'file': f, 'status': 'FAIL'})
    except:
        results.append({'file': f, 'status': 'TIMEOUT'})
    
    if i % 50 == 0:
        json.dump(results, open(out, 'w'), indent=2)

elapsed = time.time() - start
c = Counter(r['status'] for r in results)
bugs = sum(1 for r in results if r['status'] == 'BUG')
print(f'\nTime: {elapsed/60:.1f} min')
print(f'Harnesses: {total}')
print(f'PASS:  {c.get("PASS",0)}  BUG:  {bugs}')
print(f'FAIL:  {c.get("FAIL",0)}  TIMEOUT:  {c.get("TIMEOUT",0)}')
print(f'Working: {c.get("PASS",0)+bugs}/{total} = {100*(c.get("PASS",0)+bugs)/total:.1f}%')
json.dump(results, open(out, 'w'), indent=2)
print(f'Saved: {out}')
PYEOF
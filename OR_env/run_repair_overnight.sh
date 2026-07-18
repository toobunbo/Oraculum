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
out = '/home/trieudai/Oraculum/OR_env/logs/repair_overnight_results.json'
log = '/home/trieudai/Oraculum/OR_env/logs/repair_overnight_progress.log'

for i, f in enumerate(harnesses, 1):
    repo = f.split('/')[-3]
    name = os.path.basename(f)
    msg = f'[{i}/{total}] {repo}/{name}\n'
    open(log, 'a').write(msg)
    
    try:
        proc = subprocess.run([sys.executable, f, '-runs=1'], capture_output=True, text=True, timeout=TO, cwd=os.path.dirname(f))
        stderr = proc.stderr[-300:]
        if proc.returncode == 0:
            results.append({'file': f, 'status': 'PASS'})
        elif 'RuntimeError:' in stderr or 'AssertionError:' in stderr:
            results.append({'file': f, 'status': 'BUG'})
        elif 'ModuleNotFoundError' in stderr or 'ImportError' in stderr:
            mod = ''
            for line in proc.stderr.split('\n'):
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

summary = []
summary.append(f'Time: {elapsed/60:.1f} min')
summary.append(f'Results ({total} harnesses):')
for s in ['PASS', 'BUG', 'IMPORT_ERR', 'TIMEOUT', 'SEGFAULT', 'OTHER']:
    n = c.get(s, 0)
    if n: summary.append(f'  {s:15s} {n:4d} ({100*n/total:.1f}%)')
summary.append(f'Working: {c.get("PASS",0)+c.get("BUG",0)}/{total}')

json.dump(results, open(out, 'w'), indent=2)
print('\n'.join(summary))
PYEOF

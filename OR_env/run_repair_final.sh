#!/usr/bin/env bash
# Final repair loop — pre-registered plan, no cherry-picking
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
out = '/home/trieudai/Oraculum/OR_env/logs/repair_final_results.json'
log = '/home/trieudai/Oraculum/OR_env/logs/repair_final_progress.log'

for i, f in enumerate(harnesses, 1):
    repo = f.split('/')[-3]
    name = os.path.basename(f)
    open(log, 'a').write(f'[{i}/{total}] {repo}/{name}\n')
    
    # Build PYTHONPATH with repo roots for local modules
    repo_root_vhx = f'/home/trieudai/VulnHunterX/repos/python/{repo}'
    repo_root_benchmark = f'/home/trieudai/VulnHunterX/benchmarks/datasets/realvuln/repos/{repo}'
    existing_roots = [r for r in [repo_root_vhx, repo_root_benchmark] if os.path.isdir(r)]
    env = os.environ.copy()
    if existing_roots:
        env['PYTHONPATH'] = ':'.join(existing_roots) + ':' + env.get('PYTHONPATH', '')
    
    try:
        t0 = time.time()
        proc = subprocess.run(
            [sys.executable, f, '-runs=1'],
            capture_output=True, text=True, timeout=TO,
            cwd=os.path.dirname(f), env=env
        )
        stderr = proc.stderr  # full stderr, no truncation
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

# Compare with previous run
try:
    prev = json.load(open('/home/trieudai/Oraculum/OR_env/logs/repair_overnight_results.json'))
    prev_c = Counter(r['status'] for r in prev)
    print(f'\nComparison with previous run:')
    for s in ['PASS', 'IMPORT_ERR', 'TIMEOUT', 'OTHER', 'BUG']:
        old = prev_c.get(s, 0)
        new = c.get(s, 0)
        delta = new - old
        if delta != 0:
            print(f'  {s:15s}: {old:3d} → {new:3d} ({delta:+d})')
except: pass
PYEOF
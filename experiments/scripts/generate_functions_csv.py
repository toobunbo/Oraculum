#!/usr/bin/env python3
"""Generate functions.csv from source code AST for RealVuln repos.

VHX context extraction fails because codeql/python-all pack is not installed.
This script falls back to pure AST parsing, writing the same CSV format
that Oraculum's ingest step expects.
"""

import ast
import csv
import os
import sys

REPO_BASE = "/home/trieudai/VulnHunterX/benchmarks/datasets/realvuln/repos"
VHX_OUTPUT = "/home/trieudai/VulnHunterX/output/python"


def extract_functions(repo_path: str) -> list[dict]:
    """Extract all function definitions from Python files in repo_path."""
    functions = []
    for root, _dirs, files in os.walk(repo_path):
        for f in sorted(files):
            if not f.endswith(".py"):
                continue
            filepath = os.path.join(root, f)
            rel_path = os.path.relpath(filepath, repo_path)
            try:
                tree = ast.parse(open(filepath).read())
            except SyntaxError:
                continue
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    functions.append({
                        "name": node.name,
                        "file": rel_path,
                        "start_line": node.lineno,
                        "end_line": node.end_lineno or node.lineno,
                        "scope": "",
                    })
                elif isinstance(node, ast.ClassDef):
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            functions.append({
                                "name": item.name,
                                "file": rel_path,
                                "start_line": item.lineno,
                                "end_line": item.end_lineno or item.lineno,
                                "scope": node.name,
                            })
    return functions


def write_functions_csv(repo_name: str, functions: list[dict]) -> str:
    """Write functions.csv to VHX context directory."""
    context_dir = os.path.join(VHX_OUTPUT, repo_name, "context")
    os.makedirs(context_dir, exist_ok=True)
    csv_path = os.path.join(context_dir, "functions.csv")
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["name", "file", "start_line", "end_line", "scope"])
        for fn in functions:
            writer.writerow([fn["name"], fn["file"], fn["start_line"], fn["end_line"], fn["scope"]])
    return csv_path


def main():
    repos_to_process = []
    for repo in sorted(os.listdir(REPO_BASE)):
        repo_path = os.path.join(REPO_BASE, repo)
        if not os.path.isdir(repo_path):
            continue
        funcs_csv_path = os.path.join(VHX_OUTPUT, repo, "context", "functions.csv")
        # Also check if VHX output dir exists (means VHX scan was run)
        vhx_out_dir = os.path.join(VHX_OUTPUT, repo, "verification_results")
        if os.path.exists(funcs_csv_path):
            continue
        if not os.path.isdir(vhx_out_dir):
            continue  # VHX not run for this repo yet
        py_files_found = False
        for root, _dirs, files in os.walk(repo_path):
            if any(f.endswith('.py') for f in files):
                py_files_found = True
                break
        if not py_files_found:
            continue
        repos_to_process.append(repo)
    
    if not repos_to_process:
        print("All repos already have functions.csv. Nothing to do.")
        return
    
    print(f"Generating functions.csv for {len(repos_to_process)} repos...")
    for repo in repos_to_process:
        repo_path = os.path.join(REPO_BASE, repo)
        functions = extract_functions(repo_path)
        csv_path = write_functions_csv(repo, functions)
        print(f"  {repo}: {len(functions)} functions → {csv_path}")


if __name__ == "__main__":
    main()

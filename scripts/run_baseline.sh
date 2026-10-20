#!/usr/bin/env bash
#
# Baseline sweep only: deterministic + Fixed RAG + free agent + PEV, repeated
# RUNS times over the development set, with traces. Archives any prior results
# first (never deletes), then aggregates and summarizes the traces.
#
# Requires a running Ollama server (ollama serve) with the model pulled.
#
# Usage:
#   ./run_baseline.sh          # RUNS=5 (default)
#   RUNS=3 ./run_baseline.sh   # fewer repetitions for a quicker first look
#
# Note: this chains sequentially; a single PEV run makes several LLM calls per
# element, so expect roughly 2-3.5h at RUNS=5 on local Ollama.

set -euo pipefail

# Run from the project root regardless of where the script is invoked from, so
# the relative paths below (results/, main.py) resolve correctly.
cd "$(dirname "$0")/.."

RUNS="${RUNS:-5}"
export RUNS

STAMP="$(date +%Y%m%dT%H%M%S)"

# --- archive prior data (reversible: move, never delete) ------------------
if [[ -f results/results.jsonl ]]; then
  mv results/results.jsonl "results/results.archive_${STAMP}.jsonl"
  echo "Archived previous results.jsonl -> results/results.archive_${STAMP}.jsonl"
fi
# nullglob so a non-match expands to nothing instead of a literal '*.json'.
shopt -s nullglob
old_traces=(results/traces/*.json)
if (( ${#old_traces[@]} > 0 )); then
  mkdir -p "results/traces_archive_${STAMP}"
  mv "${old_traces[@]}" "results/traces_archive_${STAMP}/"
  echo "Archived ${#old_traces[@]} previous trace(s) -> results/traces_archive_${STAMP}/"
fi
shopt -u nullglob

echo "Baseline sweep starting at $(date '+%Y-%m-%d %H:%M:%S')  (RUNS=${RUNS})"
echo

# --- the sweep ------------------------------------------------------------
start=$(date +%s)
RAG=1 AGENT=1 AGENT_PEV=1 TRACE=1 uv run python main.py
end=$(date +%s)
echo
echo "Sweep finished in $(( (end - start) / 60 ))m $(( (end - start) % 60 ))s"

# --- analysis -------------------------------------------------------------
echo
echo "=================  aggregate  ================="
uv run python aggregate.py

echo
echo "=================  trace summary  ================="
uv run python trace_summary.py

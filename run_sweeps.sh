#!/usr/bin/env bash
#
# Run the three measurement sweeps from EXPERIMENTS.md back to back, then
# aggregate. Requires a running Ollama server (ollama serve) with the model
# pulled. All runs append to results/results.jsonl.
#
# Usage:
#   ./run_sweeps.sh            # RUNS=5 (default), full development set
#   RUNS=3 ./run_sweeps.sh     # override repetitions
#   ONLY=multi_tenant_saas ./run_sweeps.sh   # restrict to one architecture
#
# Stops immediately if any sweep fails (e.g. Ollama unreachable) so it does not
# run for hours into the void.

set -euo pipefail

RUNS="${RUNS:-5}"
export RUNS

# ONLY is optional; pass it through only if the caller set it.
if [[ -n "${ONLY:-}" ]]; then
  export ONLY
  echo "Restricting to architecture(s): ${ONLY}"
fi

echo "Sweeps starting at $(date '+%Y-%m-%d %H:%M:%S')  (RUNS=${RUNS})"
echo "Results append to results/results.jsonl"
echo

step() {
  # $1 = human label, rest = VAR=val ... to prefix the run
  local label="$1"; shift
  echo "=================================================================="
  echo ">>> ${label}"
  echo ">>> env: $*"
  echo ">>> started $(date '+%H:%M:%S')"
  echo "=================================================================="
  local start end
  start=$(date +%s)
  env "$@" uv run python main.py
  end=$(date +%s)
  echo ">>> ${label} finished in $(( (end - start) / 60 ))m $(( (end - start) % 60 ))s"
  echo
}

# Step 1 - baseline sweep (RAG + free agent + PEV). No traces: headline numbers.
step "Step 1/3  baseline sweep" RAG=1 AGENT=1 AGENT_PEV=1

# Step 2 - ablation sweep: baseline PEV alongside the two ablations.
step "Step 2/3  ablation sweep" \
  AGENT_PEV=1 AGENT_PEV_NOPLAN=1 AGENT_PEV_NOVERIFY=1

# Step 3 - rich-deepen variant, with traces (behaviour, not just score).
step "Step 3/3  rich-deepen sweep (with traces)" \
  AGENT_PEV=1 AGENT_PEV_RICHDEEPEN=1 TRACE=1

echo "=================================================================="
echo "All sweeps done at $(date '+%Y-%m-%d %H:%M:%S'). Aggregating:"
echo "=================================================================="
uv run python aggregate.py

echo
echo "Trace summary (Step 3 deepening behaviour):"
uv run python trace_summary.py

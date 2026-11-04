#!/usr/bin/env bash
#
# PEV ablation sweep (V1 scoring): the full variant vs. its three ablations,
# repeated RUNS times over the development set, with traces.
#
#   Config       Plan  Explore  Verify
#   agent_pev     y      y        y
#   noplan        n      y        y
#   noverify      y      y        n
#   exploreonly   n      y        n
#
# ISOLATION. The run happens in a fresh working directory *outside* the
# repository (like scripts/ollama_smoke_test.py). main.py writes results.jsonl,
# predictions and traces relative to its working directory, so nothing here can
# touch the repository's results/ (which holds the V2 capture and the files its
# annotation mapping points to) or frozen/. The outputs are copied afterwards to
# ablation_runs/<timestamp>/ in the repository (gitignored). The script refuses to
# start if that target exists, and it never moves, deletes or overwrites anything
# inside results/ or frozen/.
#
# Requires a running Ollama server with the model pulled.
#
# Usage:
#   ./scripts/run_ablation.sh                  # RUNS=5 (default)
#   RUNS=3 ./scripts/run_ablation.sh           # fewer repetitions
#   caffeinate -i ./scripts/run_ablation.sh    # keep the mac awake (multi-hour)
#   OLLAMA_MODEL=qwen2.5:7b ./scripts/run_ablation.sh   # other model
#
# Cost: 4 variants x 5 architectures x RUNS; a PEV run makes many LLM calls per
# element, so RUNS=5 is a multi-hour job.

set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
RUNS="${RUNS:-5}"
STAMP="$(date +%Y%m%dT%H%M%S)"
TARGET="${REPO}/ablation_runs/${STAMP}"

if [[ -e "${TARGET}" ]]; then
  echo "Refusing to start: ${TARGET} already exists." >&2
  exit 4
fi

# Guard: the repository's results/ and frozen/ must be byte-identical afterwards.
checksum_protected() {
  (cd "${REPO}" && find results frozen -type f -print0 2>/dev/null \
    | sort -z | xargs -0 shasum -a 256 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
}
BEFORE="$(checksum_protected)"

SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/threatmodel_ablation_XXXXXX")"
case "${SANDBOX}" in
  "${REPO}"/*) echo "Sandbox ${SANDBOX} is inside the repository." >&2; exit 3 ;;
esac
mkdir -p "${SANDBOX}/benchmark" "${SANDBOX}/data"
cp "${REPO}"/benchmark/*.json "${SANDBOX}/benchmark/"
cp "${REPO}/data/knowledge_base.json" "${SANDBOX}/data/"
echo "Sandbox: ${SANDBOX}"
echo "Ablation sweep starting at $(date '+%Y-%m-%d %H:%M:%S')  (RUNS=${RUNS})"
echo

start=$(date +%s)
(
  cd "${SANDBOX}"
  # Only the four ablation variants, no inherited selectors.
  env -u RAG -u AGENT -u AGENT_PEV -u AGENT_PEV_NOPLAN -u AGENT_PEV_NOVERIFY \
      -u AGENT_PEV_EXPLOREONLY -u AGENT_PEV_NODEEPEN -u AGENT_PEV_RICHDEEPEN \
      -u AGENT_PEV_ADAPTIVEDEEPEN -u HOLDOUT -u ONLY \
    PYTHONPATH="${REPO}" PYTHONDONTWRITEBYTECODE=1 \
    RUNS="${RUNS}" TRACE=1 \
    AGENT_PEV=1 AGENT_PEV_NOPLAN=1 AGENT_PEV_NOVERIFY=1 AGENT_PEV_EXPLOREONLY=1 \
    uv run --project "${REPO}" python -m main
)
end=$(date +%s)
echo
echo "Sweep finished in $(( (end - start) / 60 ))m $(( (end - start) % 60 ))s"

# Bring the outputs home. cp -R never touches results/ or frozen/.
mkdir -p "${TARGET}"
cp -R "${SANDBOX}/results" "${TARGET}/results"
rm -rf "${SANDBOX}"
echo "Outputs: ${TARGET}/results"

AFTER="$(checksum_protected)"
if [[ "${BEFORE}" != "${AFTER}" ]]; then
  echo "ISOLATION VIOLATED: results/ or frozen/ in the repository changed." >&2
  exit 3
fi
echo "Isolation holds: results/ and frozen/ are unchanged."

echo
echo "=================  aggregate  ================="
uv run python aggregate.py "${TARGET}/results/results.jsonl"

echo
echo "=================  trace summary  ================="
uv run python trace_summary.py "${TARGET}/results/traces"

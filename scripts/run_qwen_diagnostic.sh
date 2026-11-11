#!/usr/bin/env bash
#
# Model diagnostic: is situation-dependent tool choice limited by the model?
# (EXPERIMENTS.md, "Diagnostic: is situation-dependent tool choice limited by the
# model?"; the reading rules there were fixed before any Qwen output existed.)
#
# What runs: exactly two approaches on one architecture, one run each, with
# traces, with the agents, prompts, retriever and knowledge base unchanged:
#
#   agent_pev                  baseline (the three-calls deepening prompt)
#   agent_pev_adaptivedeepen   the stopping-is-valid deepening prompt
#
# Note: main.py always adds the deterministic baseline. It makes no model call,
# costs nothing, and is ignored by the report.
#
# MODES. Nothing starts a model run unless --run is given.
#   --dry-run   Print the plan, check prerequisites (a read-only model *list* request
#               to Ollama; no model runs), and exercise the sandbox wiring with the
#               deterministic approach only. Writes nothing to the repository.
#   --run       The real diagnostic. Stops with exit 2 if a prerequisite is missing.
#
# MODEL. OLLAMA_MODEL selects the model, default qwen2.5:7b.
#   OLLAMA_MODEL=llama3.1:8b ./scripts/run_qwen_diagnostic.sh --run
# The script never pulls or installs a model. If Ollama is unreachable or the model
# is not installed, it says so and exits 2.
#
# ISOLATION. The run happens in a fresh directory outside the repository (as in
# scripts/run_ablation.sh and scripts/ollama_smoke_test.py). Outputs are copied to
#   diagnostic_runs/<model>_<timestamp>/        (gitignored, never overwritten)
# The script refuses to start if that directory exists, never writes inside
# results/ or frozen/, never touches git, and checks by checksum that results/ and
# frozen/ are unchanged afterwards (exit 3 otherwise). The uncommitted V2 files in
# the working tree are not read, changed or staged.
#
# Output in the target directory: results/ (results.jsonl, predictions, traces),
# main.log, run_command.txt, diagnostic_report.json and diagnostic_report.md
# (tool calls, deepening steps, termination decision per prioritized element, LLM
# calls, tokens, runtime, as far as the existing instrumentation records them).
#
# Exit codes: 0 ok, 1 the run or the report had problems, 2 prerequisite missing,
# 3 isolation violated, 4 usage error or target exists.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/run_qwen_diagnostic.sh --dry-run | --run
  --dry-run   plan, prerequisite check and sandbox wiring; starts no model run
  --run       the real diagnostic (needs Ollama and the model installed)
Environment: OLLAMA_MODEL (default qwen2.5:7b)
EOF
}

MODE=""
case "${1:-}" in
  --dry-run) MODE="dry" ;;
  --run) MODE="run" ;;
  -h|--help) usage; exit 0 ;;
  *) usage >&2; exit 4 ;;
esac

REPO="$(cd "$(dirname "$0")/.." && pwd)"
ARCH="multi_tenant_saas"
APPROACHES="agent_pev,agent_pev_adaptivedeepen"
MODEL="${OLLAMA_MODEL:-qwen2.5:7b}"
# Same host as the default of OllamaClient (main.py does not pass another one).
OLLAMA_URL="http://localhost:11434"

if [[ ! "${MODEL}" =~ ^[A-Za-z0-9._:/-]+$ ]]; then
  echo "Refusing model name with unexpected characters: ${MODEL}" >&2
  exit 4
fi

STAMP="$(date +%Y%m%dT%H%M%S)"
SAFE_MODEL="${MODEL//[:\/]/-}"
TARGET="${REPO}/diagnostic_runs/${SAFE_MODEL}_${STAMP}"
UVRUN=(uv run --frozen --project "${REPO}")

SANDBOX=""
TAGS_FILE=""
cleanup() {
  [[ -n "${SANDBOX}" && -d "${SANDBOX}" ]] && rm -rf "${SANDBOX}"
  [[ -n "${TAGS_FILE}" && -f "${TAGS_FILE}" ]] && rm -f "${TAGS_FILE}"
  return 0
}
trap cleanup EXIT

# Selectors that would change what main.py runs; removed from the inherited env.
SELECTORS=(RAG AGENT AGENT_PEV AGENT_PEV_NOPLAN AGENT_PEV_NOVERIFY AGENT_PEV_EXPLOREONLY
           AGENT_PEV_NODEEPEN AGENT_PEV_RICHDEEPEN AGENT_PEV_ADAPTIVEDEEPEN
           HOLDOUT ONLY TRACE RUNS OLLAMA_MODEL)

checksum_protected() {
  (cd "${REPO}" && find results frozen -type f -print0 2>/dev/null \
    | sort -z | xargs -0 shasum -a 256 2>/dev/null | shasum -a 256 | cut -d' ' -f1)
}

# --- prerequisites: report, never install ----------------------------------------
check_prerequisites() {
  local missing=0
  echo "Prerequisites:"
  if command -v uv >/dev/null 2>&1; then echo "  [ok]      uv found"
  else echo "  [MISSING] uv not found on PATH"; missing=1; fi
  if command -v curl >/dev/null 2>&1; then echo "  [ok]      curl found"
  else echo "  [MISSING] curl not found on PATH"; missing=1; fi
  for f in "benchmark/${ARCH}.json" "benchmark/${ARCH}.ground_truth.json" \
           "data/knowledge_base.json"; do
    if [[ -f "${REPO}/${f}" ]]; then echo "  [ok]      ${f}"
    else echo "  [MISSING] ${f}"; missing=1; fi
  done
  TAGS_FILE="$(mktemp "${TMPDIR:-/tmp}/ollama_tags_XXXXXX")"
  if command -v curl >/dev/null 2>&1 \
     && curl -fsS --max-time 5 "${OLLAMA_URL}/api/tags" -o "${TAGS_FILE}" 2>/dev/null; then
    echo "  [ok]      Ollama reachable at ${OLLAMA_URL}"
    if command -v uv >/dev/null 2>&1; then
      if "${UVRUN[@]}" python - "${MODEL}" "${TAGS_FILE}" <<'PY'
import json, sys
wanted, path = sys.argv[1], sys.argv[2]
names = [m.get("name", "") for m in json.load(open(path)).get("models", [])]
ok = wanted in names or (":" not in wanted and f"{wanted}:latest" in names)
if not ok:
    print(f"  [MISSING] model {wanted!r} is not installed (installed: {names or 'none'})")
    print(f"            This script does not pull it. Fetch it yourself: ollama pull {wanted}")
    sys.exit(1)
print(f"  [ok]      model {wanted} installed")
PY
      then :; else missing=1; fi
    fi
  else
    echo "  [MISSING] Ollama not reachable at ${OLLAMA_URL} (start it with: ollama serve)"
    missing=1
  fi
  return "${missing}"
}

make_sandbox() {
  SANDBOX="$(mktemp -d "${TMPDIR:-/tmp}/threatmodel_diag_XXXXXX")"
  case "${SANDBOX}" in
    "${REPO}"/*) echo "Sandbox ${SANDBOX} is inside the repository." >&2; exit 3 ;;
  esac
  mkdir -p "${SANDBOX}/benchmark" "${SANDBOX}/data"
  cp "${REPO}/benchmark/${ARCH}.json" "${REPO}/benchmark/${ARCH}.ground_truth.json" \
     "${SANDBOX}/benchmark/"
  cp "${REPO}/data/knowledge_base.json" "${SANDBOX}/data/"
}

# Run main.py in the sandbox. Arguments: VAR=value pairs that enable approaches.
run_in_sandbox() {
  (
    cd "${SANDBOX}"
    local unset_args=()
    for v in "${SELECTORS[@]}"; do unset_args+=(-u "$v"); done
    env "${unset_args[@]}" \
      PYTHONPATH="${REPO}" PYTHONDONTWRITEBYTECODE=1 \
      ONLY="${ARCH}" RUNS=1 TRACE=1 OLLAMA_MODEL="${MODEL}" \
      "$@" \
      "${UVRUN[@]}" python -m main
  )
}

echo "Model diagnostic (${MODE})"
echo "  model:         ${MODEL}  (OLLAMA_MODEL, default qwen2.5:7b)"
echo "  architecture:  ${ARCH}  (development set; holdout not touched)"
echo "  approaches:    ${APPROACHES//,/, }   RUNS=1, TRACE=1"
echo "  unchanged:     agents, prompts, scorer, retriever, knowledge base, V2 files"
echo "  output:        ${TARGET}"
echo

# =============================== dry run =============================================
if [[ "${MODE}" == "dry" ]]; then
  PREREQ_OK=1
  check_prerequisites && PREREQ_OK=0 || PREREQ_OK=1
  echo
  echo "Sandbox wiring (deterministic approach only; no model is contacted):"
  BEFORE="$(checksum_protected)"
  make_sandbox
  DRY_OUT="${SANDBOX}/dry_out"
  run_in_sandbox >"${SANDBOX}/dry_main.log" 2>&1 || {
    echo "  [FAIL] main.py did not run in the sandbox:"; tail -n 15 "${SANDBOX}/dry_main.log"; exit 1; }
  "${UVRUN[@]}" python - "${SANDBOX}/results/results.jsonl" <<'PY' || exit 1
import json, sys
rows = [json.loads(l) for l in open(sys.argv[1]) if l.strip()]
bad = [r["approach"] for r in rows if r["approach"] != "deterministic"]
if bad or len(rows) != 1:
    print(f"  [FAIL] expected exactly one deterministic row, got {len(rows)} (others: {bad})")
    sys.exit(1)
print("  [ok]   one deterministic row written in the sandbox; no LLM approach ran")
PY
  [[ -d "${SANDBOX}/results/predictions" ]] && echo "  [ok]   predictions written inside the sandbox"
  echo "Reporter wiring (expects two problems: there are no LLM rows in a dry run):"
  set +e
  "${UVRUN[@]}" python "${REPO}/scripts/diagnostic_report.py" \
    --results-dir "${SANDBOX}/results" --out-dir "${DRY_OUT}" --model "${MODEL}" \
    --architecture "${ARCH}" --approaches "${APPROACHES}" 2>&1 | sed 's/^/  /'
  RC=${PIPESTATUS[0]}
  set -e
  [[ "${RC}" == "1" && -f "${DRY_OUT}/diagnostic_report.md" ]] \
    && echo "  [ok]   reporter ran and listed the missing rows as problems" \
    || { echo "  [FAIL] reporter exit ${RC}, unexpected"; exit 1; }
  AFTER="$(checksum_protected)"
  if [[ "${BEFORE}" != "${AFTER}" ]]; then
    echo "ISOLATION VIOLATED: results/ or frozen/ changed." >&2; exit 3
  fi
  echo "  [ok]   isolation: results/ and frozen/ unchanged; nothing written to ${REPO}/diagnostic_runs"
  echo
  echo "Planned command for the real run:"
  echo "  ./scripts/run_qwen_diagnostic.sh --run            # model: ${MODEL}"
  echo "  (before it: load the model without generating; scripts/run_qwen_diagnostic.sh does this"
  echo "   with an empty /api/generate request, because the client times out after 120 s per call)"
  if [[ "${PREREQ_OK}" != "0" ]]; then
    echo
    echo "NOT READY: a real run would stop at the prerequisites above (exit 2)."
  else
    echo
    echo "READY: prerequisites are met."
  fi
  exit 0
fi

# =============================== real run ============================================
if ! check_prerequisites; then
  echo
  echo "Prerequisites missing. Nothing was started, installed or written." >&2
  exit 2
fi
if [[ -e "${TARGET}" ]]; then
  echo "Refusing to start: ${TARGET} already exists." >&2
  exit 4
fi

BEFORE="$(checksum_protected)"
GIT_BEFORE="$(git -C "${REPO}" status --porcelain 2>/dev/null || true)"
make_sandbox
echo
echo "Sandbox: ${SANDBOX}"

# Load the model without generating, so a cold load does not hit the client's 120 s
# per-call timeout. Not a model run; failure here is only a warning.
echo "Loading ${MODEL} (empty request, no generation)..."
curl -fsS --max-time 900 "${OLLAMA_URL}/api/generate" \
  -d "{\"model\":\"${MODEL}\"}" -o /dev/null 2>/dev/null \
  && echo "  loaded" || echo "  WARNING: preload failed; the first call may load the model"

echo "Run starting at $(date '+%Y-%m-%d %H:%M:%S')"
start=$(date +%s)
set +e
run_in_sandbox AGENT_PEV=1 AGENT_PEV_ADAPTIVEDEEPEN=1 2>&1 | tee "${SANDBOX}/main.log"
RC=${PIPESTATUS[0]}
set -e
end=$(date +%s)
echo
echo "main exited with ${RC} after $(( (end - start) / 60 ))m $(( (end - start) % 60 ))s"

mkdir -p "${TARGET}"
[[ -d "${SANDBOX}/results" ]] && cp -R "${SANDBOX}/results" "${TARGET}/results"
cp "${SANDBOX}/main.log" "${TARGET}/main.log"
{
  echo "model=${MODEL}"
  echo "architecture=${ARCH}"
  echo "approaches=${APPROACHES}"
  echo "env: ONLY=${ARCH} RUNS=1 TRACE=1 OLLAMA_MODEL=${MODEL} AGENT_PEV=1 AGENT_PEV_ADAPTIVEDEEPEN=1"
  echo "command: python -m main (cwd = sandbox outside the repository)"
  echo "main_exit_code=${RC}"
  echo "started=$(date -r "${start}" '+%Y-%m-%dT%H:%M:%S')"
  echo "finished=$(date -r "${end}" '+%Y-%m-%dT%H:%M:%S')"
} > "${TARGET}/run_command.txt"

REPORT_RC=0
"${UVRUN[@]}" python "${REPO}/scripts/diagnostic_report.py" \
  --results-dir "${TARGET}/results" --out-dir "${TARGET}" --model "${MODEL}" \
  --architecture "${ARCH}" --approaches "${APPROACHES}" \
  --ollama-tags "${TAGS_FILE}" || REPORT_RC=$?

echo
[[ -f "${TARGET}/diagnostic_report.md" ]] && cat "${TARGET}/diagnostic_report.md"

AFTER="$(checksum_protected)"
if [[ "${BEFORE}" != "${AFTER}" ]]; then
  echo "ISOLATION VIOLATED: results/ or frozen/ in the repository changed." >&2
  exit 3
fi
echo "Isolation holds: results/ and frozen/ are unchanged."
GIT_AFTER="$(git -C "${REPO}" status --porcelain 2>/dev/null || true)"
if [[ "${GIT_BEFORE}" != "${GIT_AFTER}" ]]; then
  echo "NOTE: the repository's git status differs from before the run. This script changed" >&2
  echo "      nothing there (outputs are gitignored); check for edits made meanwhile." >&2
fi
echo "Outputs: ${TARGET}"
echo "One run per approach is a diagnostic hint, not a rate."

if [[ "${RC}" != "0" || "${REPORT_RC}" != "0" ]]; then
  exit 1
fi

# Experiment Log

A running record of experimental conditions and decisions, so every figure in
`RESULTS.md` can be traced back to how it was produced. Newest entries first.

## Fixed conditions (unless noted per run)

- **Model:** Ollama `llama3.1:8b`, `temperature=0` (set in `OllamaClient`).
- **Knowledge base:** the 23-snippet corpus in `data/knowledge_base.json`,
  shared identically by `rag`, `agent`, and `agent_pev`.
- **Retriever:** `KeywordRetriever` (deterministic weighted token overlap).
- **Development set** (building / diagnosing): `simple_web_api`,
  `webapp_with_auth`, `microservices_async`, `cloud_ingest_pipeline`,
  `multi_tenant_saas`.
- **Holdout test set** (untouched until the final evaluation):
  `cicd_pipeline`, `mobile_banking`.
- **Results log:** each run appended to `results/results.jsonl`; aggregated with
  `aggregate.py`. Agent execution traces written to `results/traces/` with
  `TRACE=1` and summarized with `trace_summary.py`.

## Approaches and variants

| Label | Description |
|---|---|
| `deterministic` | Rule-based STRIDE baseline, no LLM. |
| `rag` | Fixed RAG workflow. |
| `agent` | Free tool-calling loop. |
| `agent_pev` | Plan–Explore–Verify agent (`DESIGN_agent_pev.md`, frozen). |

Planned ablation variants of `agent_pev` (baseline `agent_pev` stays unchanged):
`agent_pev` without Plan, `agent_pev` without Verify, and a context-rich
deepening variant.

---

## 2026-10-19 — Freeze before ablations + trace failure-cause fix

**State frozen for the next phase.** Committed the trace tooling and a
correctness fix to the deepening trace.

**Trace fix (important for the failure analysis).** The earlier deepening trace
could not tell *"the model chose not to explore"* from *"the model could not
produce a valid action"* — both ended on one path recorded as `used=false`.
`DeepenStep` now records `raw_response`, `parsed_action`, `tool_success`, and a
`termination_reason` (`done` / `invalid_json` / `unknown_tool` / `tool_error` /
`budget_exhausted`). `PevTrace.deepened_elements()` now counts an element only
when a deepening tool call actually **succeeded**, not merely when an attempt
was recorded.

**Consequence for earlier traces.** The 10 traces from the first `TRACE=1`
sweep (archived under `results/traces_archive_*`) predate this fix and lack
`termination_reason`. The earlier observation "0/20 prioritized elements
deepened" is therefore **not yet interpretable** as a deliberate choice; it must
be re-measured with the fixed trace before any claim about *why* deepening does
not happen.

**Housekeeping.** The old `results/results.jsonl` mixed runs across several
sessions (deterministic logged 5–8× per architecture, agents 1–2×), so it was
unusable for aggregation. Archived to `results/results.archive_*.jsonl`; the log
starts clean for the multi-run sweep.

### First exploratory sweep (superseded — single run, do not cite)

`RUNS=1 AGENT=1 AGENT_PEV=1 TRACE=1`, development set. One run per
configuration, so **no variance** and not citable. Kept only as an early signal.
Headline observation on the hard domain `multi_tenant_saas`: `agent_pev` reached
hard-recall 5/6 vs. the free `agent` 1/6, i.e. the structured pipeline closed
the agent's gap on the hardest architecture. To be confirmed by the `RUNS=5`
sweep.

### Next

1. `RUNS=5` sweep on the development set for all approaches (means + std).
2. Ablations: `agent_pev` without Verify, then without Plan.
3. Re-measure deepening with the fixed trace; test a context-rich deepening
   prompt as a new variant.

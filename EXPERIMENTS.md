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

Ablation / experiment variants of `agent_pev` (baseline `agent_pev` stays
unchanged; each is a separate approach label, selectable via env var):

| Variant | Env var | Change | Research question |
|---|---|---|---|
| `agent_pev_noplan` | `AGENT_PEV_NOPLAN=1` | Plan phase skipped (no priorities/hypotheses, so no deepening) | Does planning improve detection? |
| `agent_pev_noverify` | `AGENT_PEV_NOVERIFY=1` | Verify phase skipped (keep all candidates) | Does Verify actually improve precision? |
| `agent_pev_richdeepen` | `AGENT_PEV_RICHDEEPEN=1` | Deepening prompt enriched with the element, plan hypothesis, retrieved knowledge, and tool purposes | Does more context make the model actually investigate, instead of stopping immediately? |

The three switches are independent (`use_plan`, `use_verify`, `rich_deepen`);
the default reproduces the frozen baseline exactly.

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

## How to run the measurements

Requires a running Ollama server (`ollama serve`) and the model pulled
(`ollama pull llama3.1:8b`). All runs append to `results/results.jsonl`;
aggregate with `aggregate.py` (now also reports mean LLM calls / retrieval
calls / tokens so quality can be weighed against cost).

**Step 0 — smoke test first (not for conclusions).** One run, one architecture,
every PEV variant, with traces. Confirms each variant completes and writes a
valid trace before committing to the long sweep:

```bash
RUNS=1 ONLY=multi_tenant_saas \
  AGENT_PEV=1 AGENT_PEV_NOPLAN=1 AGENT_PEV_NOVERIFY=1 AGENT_PEV_RICHDEEPEN=1 \
  TRACE=1 uv run python main.py
uv run python trace_summary.py
```

**Step 1 — baseline sweep (quality + cost, means + std).** No traces (keeps it
faster; traces are for diagnosis, not headline numbers):

```bash
RUNS=5 RAG=1 AGENT=1 AGENT_PEV=1 uv run python main.py
uv run python aggregate.py
```

**Step 2 — ablation sweep.** Baseline alongside the two ablations, so the deltas
are directly comparable:

```bash
RUNS=5 AGENT_PEV=1 AGENT_PEV_NOPLAN=1 AGENT_PEV_NOVERIFY=1 uv run python main.py
uv run python aggregate.py
```

**Step 3 — rich-deepen variant (behaviour, so keep traces).** Compare the real
deepening rate against the baseline via the trace summary:

```bash
RUNS=5 AGENT_PEV=1 AGENT_PEV_RICHDEEPEN=1 TRACE=1 uv run python main.py
uv run python trace_summary.py
```

> Cost warning: a single PEV run makes several LLM calls per element. The full
> ablation sweep is ~100 agent runs plus RAG and the free agent, so expect well
> over an hour on local Ollama. Run Step 0 first.

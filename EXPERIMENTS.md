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

## 2026-10-20 — Deepening failure analysis and acceptance criteria

**Deepening is not adaptive (measured, not assumed).** After the empty-response
fix, the PEV agent issues real tool calls on 100/100 prioritized elements, but
inspecting the stored `parsed_action` of every deepening step shows the calls
are not meaningful exploration:

- **300 deepening tool calls, all `search_knowledge`; `get_connections`: 0.**
  The agent never uses the connection-exploration tool (the one that could
  surface shared-resource / tenant-isolation threats).
- **35/100 elements issued at least one word-for-word identical repeat query.**
  With a deterministic retriever such a repeat returns the same snippets, i.e.
  is information-free.
- **Every element ends on `budget_exhausted`, never `done`.** The agent spends
  its full 3-call budget regardless of the element.

Conclusion: the agent executes its actions (goal 1) but does not yet make
sensible, information-gaining decisions (goal 2). This explains mechanistically
why deepening produced no quality gain — little new information entered.

**Status of the current numbers.** The 5-run baseline ("RAG wins on 4/5") is a
**development-phase finding**, not the final result, because the agent was still
being debugged and does not yet meet the criteria below.

### Acceptance criteria for a "functioning" adaptive agent (set before tuning)

Fixed in advance so the agent is not tuned until it happens to beat RAG. The
agent need not beat RAG — that is the question — but it must:

1. Choose sensibly among `search_knowledge`, `get_connections`, and `done`
   (not call one tool exclusively).
2. Not repeat identical search queries.
3. Produce tool calls that return genuinely new, relevant information.
4. Not be required to exhaust its budget on every element (early `done` allowed
   and expected when enough is known).

Only after these hold do we freeze the implementation and run the final
comparison (including the untouched holdout set).

## 2026-10-20 — Deepening ablation and the adaptive-prompt iteration (n=1, multi_tenant_saas)

One diagnostic run each on `multi_tenant_saas` (dev architecture). n=1, so these
are qualitative signals, not statistics; threat-level keys (`matched_keys` /
`missed_keys`) were compared, not just counts.

| Variant | deepen outcome | tool calls | F1 | matched / missed |
|---|---|---|---|---|
| `agent_pev` (baseline) | `budget_exhausted` ×4 | 3 `search_knowledge` per element, 0 `get_connections` | 0.52 | 8 / 4 |
| `agent_pev_nodeepen` | — (no deepening) | 0 | 0.48 | 8 / 4 |
| `agent_pev_adaptivedeepen` | `done` ×4 | 0 | 0.48 | 8 / 4 |

Findings:

1. **The agent's deepening decision is prompt-framed, not situation-driven.**
   The baseline prompt ("you have 3 steps") makes it spend all three every
   time; the adaptive prompt ("stopping is good, only investigate an open
   question") makes it stop immediately every time. Neither produced
   element-dependent behaviour. Acceptance criterion 1 (choose sensibly among
   the tools) is **not met** by either prompt on this model.

2. **Deepening changed no threat match.** `agent_pev` and
   `agent_pev_adaptivedeepen` produced byte-identical `matched_keys` and
   `missed_keys` — the three extra tool calls per element did not add or remove
   a single detected threat.

3. **The only measurable effect of deepening was precision.** Baseline avoided
   2 false positives (F1 0.52 vs 0.48, same 8 true positives), i.e. the extra
   context slightly helped rejection, not discovery. Weak at n=1.

Interpretation (scoped): with `llama3.1:8b`, the decision *whether* to explore
was governed by prompt wording rather than by the element's actual information
need. This points to a model-capability limit for adaptive tool use, not a
prompt bug — the same model handles Plan/Explore/Verify JSON fine. A
tool-calling-tuned model is the natural next comparison, changing only
`OLLAMA_MODEL`.

### Next

1. Optional: repeat the three-way comparison with a tool-calling-tuned model
   (e.g. `OLLAMA_MODEL=qwen2.5:7b`) to test the model-capability hypothesis.
2. Freeze the implementations and run the final comparison on the untouched
   holdout set (`cicd_pipeline`, `mobile_banking`).

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

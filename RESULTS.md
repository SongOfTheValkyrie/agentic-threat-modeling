# Results

Comparison of four threat-modeling approaches across five benchmark
architectures of increasing complexity. The LLM-backed approaches used **Ollama
`llama3.1:8b`** at `temperature=0`. Figures are the mean over a **5-run sweep**
per configuration (`RUNS=5`); at temperature 0 the content was identical across
repeats (variance ±0.00), so only latency varied. The aggregated run log is in
`results/results.jsonl`; see `EXPERIMENTS.md` for exact conditions.

> These are scoped, current measurements, not final conclusions. The ground
> truth is AI-drafted and still needs domain validation; the agent and RAG
> share one knowledge base, so this compares retrieval *orchestration*, not
> access to new information. `multi_tenant_saas` was used to diagnose and fix an
> agent bug (below), so it is a development architecture, not a held-out test.
> See "Caveats and limitations" before citing.

## The four approaches

| Label | Approach |
|---|---|
| `deterministic` | Rule-based STRIDE baseline, no LLM |
| `rag` | Fixed RAG workflow (per-element retrieve → prompt → parse) |
| `agent` | Free tool-calling loop |
| `agent_pev` | Plan–Explore–Verify agent (structured hybrid) |

## Overall F1 by architecture (mean of 5 runs)

| Architecture | difficulty focus | Deterministic | Fixed RAG | Free agent | PEV agent |
|---|---|---|---|---|---|
| simple_web_api | easy/medium | 0.40 | **0.71** | 0.55 | 0.57 |
| webapp_with_auth | trust boundaries | 0.54 | **0.60** | 0.16 | 0.47 |
| microservices_async | mostly easy | **0.81** | 0.58 | 0.19 | 0.48 |
| cloud_ingest_pipeline | hard (AWS config) | 0.38 | **0.56** | 0.44 | 0.45 |
| multi_tenant_saas | hard (authorization) | 0.50 | **0.62** | 0.25 | 0.52 |

Fixed RAG has the best F1 on four of five architectures; the deterministic
baseline wins only on `microservices_async` (≈68% easy threats that fixed rules
cover perfectly). The PEV agent beats the free agent everywhere but **never
reaches Fixed RAG**.

## Recall on the hard class

| Architecture | Deterministic | Fixed RAG | Free agent | PEV agent |
|---|---|---|---|---|
| cloud_ingest_pipeline | 0.00 | **0.71** | 0.29 | 0.43 |
| multi_tenant_saas | 0.00 | **0.83** | 0.17 | **0.83** |

On `multi_tenant_saas` the PEV agent matches Fixed RAG on hard recall (0.83);
on `cloud_ingest_pipeline` RAG is clearly ahead (0.71 vs 0.43).

## Cost: quality is not free

Mean per architecture, from the run log. This is the crux of the research
question — the PEV agent costs several times more for lower quality.

| Architecture | Fixed RAG (F1 / llm_calls / latency) | PEV agent (F1 / llm_calls / latency) |
|---|---|---|
| simple_web_api | 0.71 / 3 / 17s | 0.57 / 13 / 62s |
| webapp_with_auth | 0.60 / 12 / 62s | 0.47 / 37 / 189s |
| microservices_async | 0.58 / 18 / 98s | 0.48 / 55 / 286s |
| cloud_ingest_pipeline | 0.56 / 11 / 63s | 0.45 / 35 / 185s |
| multi_tenant_saas | 0.62 / 11 / 64s | 0.52 / 35 / 200s |

The PEV agent uses roughly **3× the LLM calls and ~3× the latency** of Fixed RAG
while scoring lower on F1 in every case.

## The agent uses its autonomy — and it still does not help

A bug initially disabled the PEV agent's adaptive deepening: the deepening chat
ended on an assistant message, so the model received nothing to answer and
returned an empty string (recorded as `invalid_json`). Deepening therefore never
ran (0 successful extra tool calls). After the fix (append findings to the user
turn), deepening works across **every** architecture:

- **100/100 prioritized elements now make a successful extra tool call**
  (`trace_summary.py`), up from 0.
- Every deepening sequence ends on `budget_exhausted`, never on `done` — the
  model always wants to keep exploring and runs into the 3-call limit.

Despite the agent now demonstrably using its autonomous exploration, its F1
stays below Fixed RAG on all five architectures. The free agent, separately,
calls `search_knowledge` **0 times in all 25 runs**: it inspects every element
but never retrieves security knowledge, which explains its weak coverage.

So the result is not "the agent was broken." The agent works as designed and
still does not beat a fixed retrieval workflow here — at substantially higher
cost.

## Key findings

1. **Fixed RAG is the best approach in this benchmark**, leading on F1 on four
   of five architectures and reaching the hard threats in both hard domains
   (recall 0.71 and 0.83). This is a *relative* result: at F1 ≈ 0.56–0.71 RAG is
   the best of the four, not necessarily strong in absolute terms. Its main
   weakness is precision (0.47–0.83) — but see the ground-truth caveat.

2. **The deterministic baseline is precise but blind to hard threats.**
   Precision 1.00 everywhere, all easy threats covered, hard-class recall 0.00
   in both hard domains.

3. **The free agent under-performs because it never retrieves.** Full element
   coverage (all runs `finished`, step budget never exhausted) but
   `search_knowledge` is used 0 times, so it reports only 3–6 threats.

4. **The PEV agent now genuinely explores, and still loses to RAG.** With the
   deepening fix it issues real tool calls on 100/100 prioritized elements, yet
   its F1 trails Fixed RAG everywhere while costing ~3× the LLM calls and
   latency. Its explore phase is structurally close to Fixed RAG (forced
   retrieval + full coverage); the added plan/verify/deepening machinery did not
   lift it above RAG in this setup.

5. **Answer to the research question (scoped).** *In our benchmark, with a small
   local model, Fixed RAG achieved better threat-modeling quality than both the
   free agent and the structured PEV agent, at a fraction of the cost. Even
   after fixing the agent so that it provably uses its autonomous exploration,
   that exploration produced no measurable advantage over fixed retrieval.* This
   does not generalize to agentic AI as such, nor to stronger models or more
   sophisticated agents (see caveats).

## Caveats and limitations

- **Temperature 0 → zero content variance.** Across the 5-run sweep, every
  LLM-backed approach produced identical threats each repeat (only latency
  varied). The n=5 sweep confirms stability but provides **no statistical
  spread**; stronger claims would need temperature > 0 and more seeds.
- **Ground truth is the biggest risk (validate first).** The architectures are
  synthetic and their ground truth AI-drafted. If incomplete, precision/recall
  are distorted — an apparent RAG false positive may be a legitimate threat
  simply absent from the ground truth. Review before further comparisons.
- **`multi_tenant_saas` is a development architecture, not a test.** It was used
  to diagnose and fix the deepening bug, so the agent's good hard-recall there
  (0.83) must not be read as held-out evidence. The holdout set
  (`cicd_pipeline`, `mobile_banking`) remains untouched for the final evaluation.
- **Shared knowledge base.** The agent has no tool that fetches information RAG
  cannot obtain; its only extra capability is exploring connections and choosing
  queries. This tests fixed vs. dynamic retrieval orchestration over the same
  knowledge, not the fuller promise of agentic AI (new sources, live CVE lookups,
  code analysis). Scope claims accordingly.
- **Deepening always hits the budget.** `budget_exhausted` on 100/100 means the
  model never chose to stop; more tool calls are not the same as useful
  exploration, and verify discards ~28% of proposed candidates. Whether the
  exploration surfaces genuinely new, correct threats is not established.
- **Small model only.** The mediocre absolute F1 (~0.6) is likely in part a
  model-capacity limit; a stronger, tool-calling-tuned model might change the
  picture and is the natural next comparison.

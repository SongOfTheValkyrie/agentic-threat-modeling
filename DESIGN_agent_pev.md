# Design: StructuredAgentThreatModeler (Plan–Explore–Verify)

**Status: FROZEN** — this design was fixed before implementation and before
seeing any benchmark results for this variant. Any change made in reaction to
benchmark scores must be recorded as a new, separately named variant, not
edited into this one. This document exists so that the "specified in advance"
claim is auditable.

## Motivation (from diagnosis of the original agent)

Trace analysis of the original `agent` (llama3.1:8b) over the five development
architectures showed:

- It never hit the 40-step limit (used 9–30 steps).
- It called `search_knowledge` **0 times** in every run — it never used the
  retrieval capability that makes Fixed RAG strong.
- It called `report_threat` **exactly 8 times** in every run and then stopped.
- Every missed ground-truth threat was on an element it *had* inspected
  (information was available, no threat reported).

> **Note on the "8 reports":** The consistent count of 8 `report_threat` calls
> is an **observation** across these runs, not a proven technical limit. We did
> not identify a hard cap in the code or model; it may be a behavioural
> tendency of this model/prompt. It is reported as an observation only.

So the two concrete, measured problems this variant targets are:
**(a) retrieval was never used**, and **(b) threat coverage was systematically
low (under-reporting)**.

## Variant overview

`StructuredAgentThreatModeler` (approach label `agent_pev`) is the **fourth**
approach, alongside deterministic, Fixed RAG, and the original `agent` (which
stays **unchanged** as a baseline). It is a hybrid agentic workflow:
**guaranteed base coverage** (deterministic iteration over all elements) with
**adaptive depth** (model-driven extra tool calls). It uses the **same**
`OllamaClient`, the **same** `KeywordRetriever`, and the **same** 23-snippet
knowledge base as Fixed RAG.

## Phases

### 1. Plan (one LLM call)
Input: component and flow list (no details). Output: structured JSON with
- **prioritization** of security-critical components,
- suspected **trust boundaries** between components,
- short **investigation hypotheses** per prioritized element.

The plan is **steering, not selecting**: it does not decide which elements are
visited (all are), it governs the **depth and choice of adaptive deepening** in
Explore. Prioritized elements / elements with a hypothesis get more adaptive
investigation.

### 2. Explore (deterministic iteration over ALL elements)
For every component and every data flow, a fixed micro-sequence:
- `inspect` (details incl. config) — automatic
- **mandatory `search_knowledge`** — automatic, query built from element
  attributes using the same query logic as Fixed RAG (identical retrieval)
- **adaptive deepening, plan-driven** — if the plan prioritized this element /
  attached a hypothesis / flagged a trust boundary, the model may issue
  additional tool calls (`get_connections`, a second targeted
  `search_knowledge`). Non-prioritized elements get base coverage only.
- the model proposes **candidate threats** for this element (not yet final).

**Maximum adaptive tool calls per element: 3** (beyond the mandatory
inspect + search). This bounds cost and latency. The mandatory inspect and the
one mandatory search do not count toward this limit.

### 3. Verify (per element / small batches)
Candidate threats are validated **per element (or in small batches)**, one LLM
call per batch, checking plausibility and architecture relevance and discarding
unjustified candidates. Smaller, focused context per check suits the small
model better than one overloaded prompt.

### 4. Report (no LLM call, deterministic)
Confirmed threats from all verify batches are **merged deterministically** into
the final `Threat` list. No per-threat `report_threat` calls; no implicit cap.

## Logging (added for this comparison)

Per run, in addition to F1 / precision / recall / latency / threat count:
- `retrieval_calls` — number of `search_knowledge` invocations
- `llm_calls` — number of LLM invocations (plan + explore + verify)
- `tokens` — sum of Ollama `prompt_eval_count` + `eval_count` across calls

`OllamaClient` is extended to return token counts; `results.py` gains optional,
backward-compatible fields. These metrics are also recorded for the other
approaches where applicable (RAG and the original agent make LLM calls; the
deterministic baseline makes none).

## Conditions honored

- Same retriever, knowledge base, and LLM as Fixed RAG.
- Deterministic iteration over all components and data flows (full coverage).
- Mandatory knowledge search per element; additional tool calls/searches chosen
  adaptively by the model (capped at 3 per element).
- Explicit verification phase, per element / small batch, merged
  deterministically.
- Collected structured output instead of individual `report_threat` calls.
- The original `agent` and Fixed RAG remain unchanged.

## Changes vs. the original agent

1. Control flow: free agentic loop → Plan–Explore–Verify pipeline with
   deterministic element iteration.
2. Retrieval: never used → mandatory per element + plan-driven extra searches.
3. Reporting: individual calls (observed ~8) → collected JSON output.
4. Verification: none → per-element/batch verify phase.
5. Planning: none → plan phase steers deepening.
6. Logging: tokens, retrieval calls, and LLM calls added.

## Methodological limitations (to document in results)

1. **Multiple variables changed at once** (plan, forced retrieval, verify,
   output format). Any improvement is attributable to the **variant as a
   whole**, not to a single component. No ablations are run.
2. **Forced retrieval + deterministic iteration make Explore structurally
   similar to Fixed RAG.** If this agent wins, the effect may come largely from
   "Fixed-RAG-like coverage + plan/verify" rather than from genuine autonomy.
3. **Same small model and same knowledge base** → all prior caveats hold
   (model-capacity ceiling; shared KB means this tests orchestration, not access
   to new information).
4. **Specified once, measured once.** Post-hoc tuning against benchmark scores
   is excluded by design; such changes would become a new named variant.

## Evaluation plan

The five existing architectures are treated as a **development benchmark**
(used while building and diagnosing). For the final evaluation we additionally
introduce previously **unused holdout test architectures**, to reduce the risk
of having implicitly overfit designs/vocabulary to the development set. The
final comparison covers four approaches — deterministic, Fixed RAG, original
agent, `agent_pev` — on the same architectures, knowledge base, and model
conditions, reporting F1, hard-recall, precision, latency, tokens, and
retrieval/LLM-call counts.

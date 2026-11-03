"""Deterministic stub LLM and golden-run harness (offline, no Ollama).

Purpose (V2 gate G1): prove that logging-only changes do not alter behavior.
The harness runs every approach against a scripted stub LLM and records, per
run, (a) the returned threats, (b) a hash of every request sent to the LLM,
(c) usage counters, and (d) the agent trace. The same code produces

* the *golden* fixture, by running it against the tree archived from the git
  tag ``v1-benchmark`` (see ``generate`` below), and
* the *actual* output in the test suite, by running it against the working tree.

Because request hashes cover the exact prompt text, any change to a prompt, to
the order or number of LLM calls, or to what the code sends, changes a hash and
fails the comparison.

Design rules for the stub:

* Requests are classified by **literal text markers copied from the V1
  prompts**, never by importing the prompt constants from the code under test.
  Otherwise a prompt edit would move the stub's markers along with it and go
  unnoticed. A request the stub cannot classify is recorded as ``unclassified``.
* Responses are pure functions of the request content (plus per-run counters
  for the multi-turn agents), so a run is fully reproducible.
* Hashing uses SHA-256, never Python's ``hash()``, so results do not depend on
  ``PYTHONHASHSEED``.

Regenerating the golden fixture (from the repository root)::

    git archive v1-benchmark | tar -x -C /tmp/v1_tree
    cp tests/golden_support.py /tmp/v1_tree/tests/   # mkdir -p first
    cd /tmp/v1_tree && PYTHONPATH=. \\
        GOLDEN_SOURCE_TAG=v1-benchmark GOLDEN_SOURCE_COMMIT=<tag commit> \\
        <repo>/.venv/bin/python tests/golden_support.py --out <repo>/tests/fixtures/golden_v1.json
"""

import argparse
import hashlib
import json
import os
import re
import sys
from collections.abc import Callable
from pathlib import Path

import src
from src.agent.modeler import AgentThreatModeler
from src.agent.structured import StructuredAgentThreatModeler
from src.deterministic.modeler import DeterministicThreatModeler
from src.models.architecture import Architecture
from src.models.loader import load_architecture
from src.RAG.knowledge import load_knowledge_base
from src.RAG.pipeline import RagThreatModeler
from src.RAG.retriever import KeywordRetriever

STRIDE = [
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
]

# Architectures covered by the golden fixture: a minimal one and one with
# config, an external entity, and several flows.
ARCHITECTURES = ["simple_web_api", "multi_tenant_saas"]

# Files whose content must stay byte-identical across the logging change
# (matching, retrieval, prompts of RAG and the free agent, data). Their
# checksums are stored as provenance and compared to the V1 manifest in tests.
PROVENANCE_FILES = [
    "src/evaluation/evaluator.py",
    "src/RAG/retriever.py",
    "src/RAG/query_builder.py",
    "src/RAG/pipeline.py",
    "src/agent/modeler.py",
    "src/agent/structured.py",
    "data/knowledge_base.json",
]


def _h(text: str) -> int:
    """Stable integer hash of a string (independent of PYTHONHASHSEED)."""
    return int(hashlib.sha256(text.encode("utf-8")).hexdigest(), 16)


def sha16(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()[:16]


_ID_RE = re.compile(r'"id":\s*"([^"]+)"')
_DEEPEN_BASELINE_ID_RE = re.compile(r"Element \((?:component|data_flow)\): ([^\s.]+)\.")
_VERIFY_CANDIDATES_RE = re.compile(
    r"Proposed threats for this element:\s*(\{.*\})\s*Return JSON", re.DOTALL
)


def _threat_payload(element_id: str) -> str:
    """Candidate threats for one element, as a JSON string.

    Includes cases the parsers must handle: a repeated category, an invalid
    category, and an empty description.
    """
    h = _h(element_id)
    items = []
    for i in range(1 + h % 3):
        category = STRIDE[(h >> (4 * i)) % 6]
        items.append({
            "category": category,
            "description": f"{category} threat {i} on {element_id}",
            "mitigation": f"mitigate {category} on {element_id}",
        })
    if h % 4 == 0:
        first = items[0]
        items.append({**first, "description": f"second {first['category']} on {element_id}"})
    if h % 5 == 0:
        items.append({"category": "nonsense", "description": "invalid category", "mitigation": "x"})
    if h % 6 == 0:
        items.append({"category": "tampering", "description": "", "mitigation": "x"})
    return json.dumps({"threats": items})


class StubLLM:
    """Scripted LLM double. Not a model: a deterministic function of requests."""

    name = "stub"

    def __init__(self, architecture: Architecture):
        self.components = [c.id for c in architecture.components]
        self.flows = [f.id for f in architecture.data_flows]
        # Plan priorities: a few components, one flow, and an unknown id. The
        # position in this list decides how deepening behaves (see _deepen).
        self.priorities = self.components[:4] + self.flows[:1] + ["ghost_component"]
        self.llm_calls = 0
        self.tokens = 0
        self.requests: list[dict] = []
        self._agent_calls = 0
        self._deepen_calls: dict[str, int] = {}
        self._agent_script = self._build_agent_script()

    # --- public LLMClient surface -----------------------------------------

    def complete(self, prompt: str, system: str | None = None) -> str:
        self.llm_calls += 1
        if system and "performing STRIDE threat modeling" in system:
            phase = "rag"
            match = _ID_RE.search(prompt)
            reply = _threat_payload(match.group(1)) if match else "{}"
        else:
            phase, reply = "unclassified", "{}"
        self._record("complete", {"prompt": prompt, "system": system}, phase)
        return reply

    def chat(self, messages: list[dict]) -> str:
        self.llm_calls += 1
        system = messages[0]["content"] if messages and messages[0]["role"] == "system" else ""
        user = messages[-1]["content"] if messages else ""
        if "by exploring it with tools" in system:
            phase, reply = "agent", self._agent_reply()
        elif "planning a STRIDE threat-modeling review" in system:
            phase, reply = "pev_plan", self._plan_reply()
        elif "analyzing ONE element of an architecture" in system:
            if any(
                marker in user
                for marker in (
                    "additional investigation step",
                    "deciding whether to investigate this",
                    "whether ONE more investigation step",
                )
            ):
                phase, reply = "pev_deepen", self._deepen_reply(user)
            elif "List the threats that genuinely apply to THIS element" in user:
                match = _ID_RE.search(user)
                phase = "pev_explore"
                reply = _threat_payload(match.group(1)) if match else "{}"
            else:
                phase, reply = "unclassified", "{}"
        elif "senior security reviewer" in system:
            phase, reply = "pev_verify", self._verify_reply(user)
        else:
            phase, reply = "unclassified", "{}"
        self._record("chat", {"messages": messages}, phase)
        return reply

    # --- bookkeeping -------------------------------------------------------

    def _record(self, kind: str, payload: dict, phase: str) -> None:
        canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:16]
        self.requests.append({"kind": kind, "phase": phase, "sha": digest})

    # --- per-phase replies --------------------------------------------------

    def _plan_reply(self) -> str:
        hypotheses = {
            element: f"check the configuration of {element}" for element in self.priorities[:2]
        }
        return json.dumps({
            "priorities": self.priorities,
            "trust_boundaries": ["public to application"],
            "hypotheses": hypotheses,
        })

    def _deepen_reply(self, user: str) -> str:
        match = _DEEPEN_BASELINE_ID_RE.search(user) or _ID_RE.search(user)
        element = match.group(1) if match else ""
        turn = self._deepen_calls.get(element, 0)
        self._deepen_calls[element] = turn + 1
        position = self.priorities.index(element) if element in self.priorities else 0

        def search(query: str) -> str:
            return json.dumps({"tool": "search_knowledge", "args": {"query": query}})

        if element in self.flows:
            # get_connections on a flow id is a tool error.
            return json.dumps({"tool": "get_connections", "args": {"component_id": element}})
        mode = position % 4
        if mode == 0:  # three successful calls, then the budget runs out
            if turn == 0:
                return search(f"{element} security")
            if turn == 1:
                return json.dumps({"tool": "get_connections", "args": {"component_id": element}})
            return search(f"{element} trust boundary")
        if mode == 1:  # one search, then done
            return search(f"{element} access") if turn == 0 else json.dumps({"tool": "done"})
        if mode == 2:  # reply without any JSON
            return "I am not sure what to investigate."
        return json.dumps({"tool": "bogus"})  # unknown tool

    def _verify_reply(self, user: str) -> str:
        match = _VERIFY_CANDIDATES_RE.search(user)
        candidates = json.loads(match.group(1))["threats"] if match else []
        element = _ID_RE.search(user)
        if element and _h(element.group(1)) % 11 == 0:
            return "no JSON from the reviewer"
        # Keep every other candidate, so Verify visibly drops some.
        kept = [c for i, c in enumerate(candidates) if i % 2 == 0]
        return json.dumps({"threats": kept})

    def _build_agent_script(self) -> list[str]:
        c, f = self.components, self.flows

        def inspect(cid: str) -> str:
            return json.dumps({"tool": "inspect_component", "args": {"component_id": cid}})

        def inspect_flow(fid: str) -> str:
            return json.dumps({"tool": "inspect_data_flow", "args": {"data_flow_id": fid}})

        def report(target: str, category: str) -> str:
            return json.dumps({"tool": "report_threat", "args": {
                "target_id": target, "category": category,
                "description": f"{category} on {target}", "mitigation": "fix it",
            }})

        script = [
            json.dumps({"tool": "list_components"}),
            "Let me think about what to look at first.",  # unparseable
            inspect(c[0]),
            inspect(c[0]),  # repeated action -> loop intervention
            json.dumps({"tool": "finish"}),  # finish before full coverage -> blocked
            json.dumps({"tool": "search_knowledge", "args": {"query": "authorization"}}),
            json.dumps({"tool": "get_connections", "args": {"component_id": c[0]}}),
        ]
        script += [inspect(x) for x in c[1:]]
        script += [inspect_flow(x) for x in f]
        script += [
            json.dumps({"tool": "bogus"}),  # unknown tool
            json.dumps({"tool": "inspect_component"}),  # missing argument
            report(c[0], "spoofing"),
            report(f[0] if f else c[0], "information_disclosure"),
            report(c[0], "weird"),  # invalid category
            report("ghost", "spoofing"),  # unknown target
            json.dumps({"tool": "finish"}),
        ]
        return script

    def _agent_reply(self) -> str:
        index = min(self._agent_calls, len(self._agent_script) - 1)
        self._agent_calls += 1
        return self._agent_script[index]


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

Factory = Callable[[StubLLM, KeywordRetriever], object]

SPECS: list[tuple[str, Factory]] = [
    ("deterministic", lambda llm, r: DeterministicThreatModeler()),
    ("rag", lambda llm, r: RagThreatModeler(llm=llm, retriever=r)),
    ("agent", lambda llm, r: AgentThreatModeler(llm=llm, retriever=r)),
    ("agent_pev", lambda llm, r: StructuredAgentThreatModeler(llm=llm, retriever=r)),
    ("agent_pev_noplan", lambda llm, r: StructuredAgentThreatModeler(
        llm=llm, retriever=r, use_plan=False)),
    ("agent_pev_noverify", lambda llm, r: StructuredAgentThreatModeler(
        llm=llm, retriever=r, use_verify=False)),
    ("agent_pev_explore_only", lambda llm, r: StructuredAgentThreatModeler(
        llm=llm, retriever=r, use_plan=False, use_verify=False)),
    ("agent_pev_nodeepen", lambda llm, r: StructuredAgentThreatModeler(
        llm=llm, retriever=r, use_deepening=False)),
    ("agent_pev_richdeepen", lambda llm, r: StructuredAgentThreatModeler(
        llm=llm, retriever=r, rich_deepen=True)),
    ("agent_pev_adaptivedeepen", lambda llm, r: StructuredAgentThreatModeler(
        llm=llm, retriever=r, adaptive_deepen=True)),
]


def run_one(factory: Factory, architecture: Architecture, retriever: KeywordRetriever) -> dict:
    llm = StubLLM(architecture)
    modeler = factory(llm, retriever)
    threats = modeler.analyze(architecture)
    tool_box = getattr(modeler, "last_tool_box", None)
    trace = getattr(modeler, "last_trace", None)
    trace_dict = None
    if trace is not None:
        trace_dict = trace.to_dict()
        trace_dict.pop("timestamp", None)  # the only wall-clock field
    return {
        "modeler_name": modeler.name,
        "threats": [t.model_dump(mode="json") for t in threats],
        "requests": llm.requests,
        "llm_calls": llm.llm_calls,
        "retrieval_calls": tool_box.retrieval_calls if tool_box is not None else None,
        "trace": trace_dict,
    }


def run_all(root: Path) -> dict:
    """Run every approach on every covered architecture against the stub."""
    retriever = KeywordRetriever(load_knowledge_base(root / "data" / "knowledge_base.json"))
    runs: dict[str, dict] = {}
    for arch_name in ARCHITECTURES:
        architecture = load_architecture(root / "benchmark" / f"{arch_name}.json")
        runs[arch_name] = {
            label: run_one(factory, architecture, retriever) for label, factory in SPECS
        }
    return runs


def provenance(root: Path) -> dict:
    return {
        "source_tag": os.environ.get("GOLDEN_SOURCE_TAG"),
        "source_commit": os.environ.get("GOLDEN_SOURCE_COMMIT"),
        "tree_checksums": {rel: sha16(root / rel) for rel in PROVENANCE_FILES},
    }


def generate(root: Path, out: Path) -> dict:
    src_path = Path(src.__file__).resolve()
    if not src_path.is_relative_to(root.resolve()):
        sys.exit(f"Refusing to generate: 'src' was imported from {src_path}, not from {root}.")
    runs = run_all(root)
    unclassified = [
        (arch, label, i)
        for arch, by_label in runs.items()
        for label, run in by_label.items()
        for i, req in enumerate(run["requests"])
        if req["phase"] == "unclassified"
    ]
    if unclassified:
        sys.exit(f"Stub could not classify requests (generator bug): {unclassified[:5]}")
    data = {"provenance": provenance(root), "runs": runs}
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(data, indent=1, sort_keys=True, ensure_ascii=False) + "\n")
    return data


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate the golden V1 fixture.")
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    generate(args.root.resolve(), args.out)
    print(f"Wrote {args.out}")

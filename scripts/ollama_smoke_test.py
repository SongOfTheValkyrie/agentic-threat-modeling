#!/usr/bin/env python3
"""Isolated Ollama smoke test: the precondition for the V2 capture run.

It checks, with a real model on one small architecture, that the pipeline runs
end to end and that the V2 logging works on real output: predictions are
stored, PEV traces carry the candidate texts, and the files agree with each
other.

Isolation guarantees:

* ``main`` runs in a temporary directory *outside* the repository, so every
  relative path it writes (``results/``, predictions, traces) lands there.
* Variables that select approaches or architectures are removed from the
  inherited environment, so nothing runs that was not asked for.
* Checksums of the repository's ``results/`` and ``frozen/`` are taken before and
  after. Any difference ends the script with exit code 3.

Exit codes: 0 ok, 1 a check failed, 2 Ollama or the model is unavailable,
3 isolation violated, 4 usage error.

``--preflight-only`` contacts Ollama's model list and runs no model.

Example::

    python scripts/ollama_smoke_test.py --preflight-only
    python scripts/ollama_smoke_test.py            # rag, agent_pev, agent_pev_noplan
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# Same value as the default host of OllamaClient (a test keeps them equal).
DEFAULT_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_ARCHITECTURE = "simple_web_api"
DEFAULT_APPROACHES = ["rag", "agent_pev", "agent_pev_noplan"]

# Directories whose content must be identical before and after the test.
PROTECTED = ["results", "frozen"]

# Result label -> environment variable that enables it in main.py.
APPROACH_ENV = {
    "rag": "RAG",
    "agent": "AGENT",
    "agent_pev": "AGENT_PEV",
    "agent_pev_noplan": "AGENT_PEV_NOPLAN",
    "agent_pev_noverify": "AGENT_PEV_NOVERIFY",
    "agent_pev_noplan_noverify": "AGENT_PEV_EXPLOREONLY",
}

# Inherited variables that would change what main.py runs.
CONTROLLED_ENV = [
    *APPROACH_ENV.values(),
    "AGENT_PEV_NODEEPEN", "AGENT_PEV_RICHDEEPEN", "AGENT_PEV_ADAPTIVEDEEPEN",
    "HOLDOUT", "ONLY", "TRACE", "RUNS", "OLLAMA_MODEL",
]

EXIT_OK, EXIT_CHECK_FAILED, EXIT_PREFLIGHT, EXIT_ISOLATION, EXIT_USAGE = 0, 1, 2, 3, 4


class OllamaUnavailable(Exception):
    """Ollama cannot be reached."""


class IsolationError(Exception):
    """The sandbox is not isolated from the repository."""


# --- isolation proof ----------------------------------------------------------


def snapshot(root: Path, names: list[str] | None = None) -> dict[str, str]:
    """Map every file under the protected directories to ``size:sha256``."""
    snap: dict[str, str] = {}
    for name in names or PROTECTED:
        base = root / name
        if not base.exists():
            continue
        for path in sorted(base.rglob("*")):
            if path.is_file():
                digest = hashlib.sha256(path.read_bytes()).hexdigest()
                snap[str(path.relative_to(root))] = f"{path.stat().st_size}:{digest}"
    return snap


def diff_snapshots(before: dict[str, str], after: dict[str, str]) -> dict[str, list[str]]:
    return {
        "added": sorted(set(after) - set(before)),
        "removed": sorted(set(before) - set(after)),
        "modified": sorted(k for k in set(before) & set(after) if before[k] != after[k]),
    }


def assert_outside_repo(path: Path, repo: Path = ROOT) -> None:
    resolved, repo = path.resolve(), repo.resolve()
    if resolved == repo or repo in resolved.parents:
        raise IsolationError(f"sandbox {resolved} is inside the repository {repo}")


# --- Ollama preflight ----------------------------------------------------------


def ollama_models(host: str, timeout: float = 5.0) -> list[str]:
    try:
        with urllib.request.urlopen(f"{host.rstrip('/')}/api/tags", timeout=timeout) as response:
            data = json.loads(response.read().decode("utf-8"))
    except (OSError, ValueError) as exc:
        raise OllamaUnavailable(f"cannot reach Ollama at {host}: {exc}") from exc
    return [m["name"] for m in data.get("models", [])]


def model_available(models: list[str], wanted: str) -> bool:
    return wanted in models or (":" not in wanted and f"{wanted}:latest" in models)


# --- sandbox -------------------------------------------------------------------


def prepare_sandbox(architecture: str, repo: Path = ROOT) -> Path:
    sandbox = Path(tempfile.mkdtemp(prefix="threatmodel_smoke_")).resolve()
    assert_outside_repo(sandbox, repo)
    (sandbox / "benchmark").mkdir()
    (sandbox / "data").mkdir()
    for suffix in (".json", ".ground_truth.json"):
        shutil.copy(repo / "benchmark" / f"{architecture}{suffix}", sandbox / "benchmark")
    shutil.copy(repo / "data" / "knowledge_base.json", sandbox / "data")
    return sandbox


def build_env(approaches: list[str], architecture: str, model: str, repo: Path = ROOT) -> dict:
    env = {k: v for k, v in os.environ.items() if k not in CONTROLLED_ENV}
    inherited = env.get("PYTHONPATH")
    env["PYTHONPATH"] = str(repo) + (os.pathsep + inherited if inherited else "")
    env["PYTHONDONTWRITEBYTECODE"] = "1"  # do not write .pyc files into the repository
    env.update({"ONLY": architecture, "TRACE": "1", "RUNS": "1", "OLLAMA_MODEL": model})
    for approach in approaches:
        env[APPROACH_ENV[approach]] = "1"
    return env


def run_main(sandbox: Path, env: dict, timeout: float) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-m", "main"],
        cwd=sandbox, env=env, capture_output=True, text=True, timeout=timeout,
    )


# --- output checks (pure; testable without Ollama) ------------------------------


def _rows(sandbox: Path) -> list[dict]:
    path = sandbox / "results" / "results.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _fields(prediction: dict) -> tuple:
    return (
        prediction["target"], prediction["category"],
        prediction["description"], prediction["mitigation"],
    )


def load_run_predictions(sandbox: Path) -> dict[str, list[tuple]]:
    """Predicted (target, category, description, mitigation) per approach."""
    out = {}
    for row in _rows(sandbox):
        record = json.loads((sandbox / row["predictions_file"]).read_text())
        out[row["approach"]] = [_fields(p) for p in record["predictions"]]
    return out


def check_outputs(
    sandbox: Path,
    approaches: list[str],
    architecture: str,
    model: str,
    require_tokens: bool = True,
) -> tuple[list[str], list[str]]:
    """Return (failures, warnings) for what one run wrote into the sandbox."""
    failures: list[str] = []
    warnings: list[str] = []
    if not (sandbox / "results" / "results.jsonl").exists():
        return ["results.jsonl was not written in the sandbox"], warnings

    by_approach: dict[str, list[dict]] = {}
    for row in _rows(sandbox):
        by_approach.setdefault(row["approach"], []).append(row)
    expected = ["deterministic", *approaches]
    for name in expected:
        if len(by_approach.get(name, [])) != 1:
            failures.append(
                f"{name}: expected exactly one result row, found {len(by_approach.get(name, []))}"
            )
    for name in sorted(set(by_approach) - set(expected)):
        failures.append(f"{name}: unexpected approach ran")

    predictions: dict[str, list[dict]] = {}
    for name in expected:
        if len(by_approach.get(name, [])) != 1:
            continue
        row = by_approach[name][0]
        expected_model = "none" if name == "deterministic" else model
        for field, want in (("model", expected_model), ("architecture", architecture)):
            if row.get(field) != want:
                failures.append(f"{name}: result row {field} is {row.get(field)!r}, want {want!r}")

        file_ref = row.get("predictions_file")
        path = sandbox / file_ref if file_ref else None
        if path is None or not path.exists():
            failures.append(f"{name}: predictions file missing ({file_ref})")
            continue
        record = json.loads(path.read_text())
        for field, want in (
            ("schema_version", 1), ("approach", name), ("model", expected_model),
            ("architecture", architecture), ("run_index", 0),
        ):
            if record.get(field) != want:
                failures.append(f"{name}: predictions {field} is {record.get(field)!r}")
        items = record["predictions"]
        if not (record["num_predictions"] == len(items) == row["num_threats"]):
            failures.append(f"{name}: prediction count differs between file and result row")
        if any(not p["description"].strip() or not p["target"] for p in items):
            failures.append(f"{name}: a prediction has an empty description or target")
        if {p["key"] for p in items} != set(row["matched_keys"]) | set(
            row["unmatched_prediction_keys"]
        ):
            failures.append(f"{name}: prediction keys differ from the keys in the result row")
        if path.stat().st_mode & 0o222:
            failures.append(f"{name}: predictions file is writable (should be read-only)")
        code = record.get("code") or {}
        if code.get("commit") is None:
            warnings.append(f"{name}: git commit not recorded")
        elif code.get("dirty"):
            warnings.append(f"{name}: tracked files differ from the commit; start the capture "
                            "run from a committed tree")
        if name != "deterministic":
            if not row.get("llm_calls"):
                failures.append(f"{name}: no LLM calls recorded")
            if require_tokens and not row.get("tokens"):
                failures.append(f"{name}: no token usage recorded")
            if not items:
                warnings.append(f"{name}: the model returned no predictions")
        predictions[name] = items

    traces_dir = sandbox / "results" / "traces"
    traces = [json.loads(p.read_text()) for p in sorted(traces_dir.glob("*.json"))] if (
        traces_dir.exists()
    ) else []
    for name in (a for a in approaches if a.startswith("agent_pev")):
        matching = [t for t in traces if t.get("agent") == name]
        if len(matching) != 1:
            failures.append(f"{name}: expected one trace file, found {len(matching)}")
            continue
        logged: list[tuple] = []
        for element in matching[0]["elements"]:
            ident = element["element_id"]
            if "proposed_threats" not in element or "confirmed_threats" not in element:
                failures.append(f"{name}/{ident}: candidate texts missing from the trace")
                continue
            for texts, keys, label in (
                (element["proposed_threats"], element["proposed_keys"], "proposed"),
                (element["confirmed_threats"], element["confirmed_keys"], "confirmed"),
            ):
                if sorted({f"{ident}:{c['category']}" for c in texts}) != keys:
                    failures.append(f"{name}/{ident}: {label} texts do not match {label}_keys")
            logged += [
                (ident, c["category"], c["description"], c["mitigation"])
                for c in element["confirmed_threats"]
            ]
        if logged != [_fields(p) for p in predictions.get(name, [])]:
            failures.append(
                f"{name}: confirmed candidates in the trace differ from the predictions"
            )
    return failures, warnings


# --- command line ----------------------------------------------------------------


def _parse(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--model", default=DEFAULT_MODEL)
    parser.add_argument("--architecture", default=DEFAULT_ARCHITECTURE)
    parser.add_argument("--approaches", default=",".join(DEFAULT_APPROACHES),
                        help=f"comma separated, from: {', '.join(APPROACH_ENV)}")
    parser.add_argument("--preflight-only", action="store_true",
                        help="check Ollama and the model, run nothing")
    parser.add_argument("--drift", action="store_true",
                        help="run a second time and report whether predictions are identical "
                             "(informational, never fails the test)")
    parser.add_argument("--keep", action="store_true", help="keep the sandbox directory")
    parser.add_argument("--timeout", type=float, default=1800.0, help="seconds per run")
    return parser.parse_args(argv)


def _isolation_report(before: dict[str, str], repo: Path) -> int:
    changes = diff_snapshots(before, snapshot(repo))
    if any(changes.values()):
        print("ISOLATION VIOLATED: the repository's results/ or frozen/ changed.")
        for kind, files in changes.items():
            for f in files:
                print(f"  {kind}: {f}")
        return EXIT_ISOLATION
    print(f"Isolation holds: {len(before)} files in results/ and frozen/ are unchanged.")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _parse(argv)
    approaches = [a.strip() for a in args.approaches.split(",") if a.strip()]
    unknown = [a for a in approaches if a not in APPROACH_ENV]
    if unknown or not approaches:
        print(f"Unknown or empty approaches {unknown}. Choose from: {', '.join(APPROACH_ENV)}")
        return EXIT_USAGE
    if not (ROOT / "benchmark" / f"{args.architecture}.json").exists():
        print(f"Unknown architecture {args.architecture!r}.")
        return EXIT_USAGE

    before = snapshot(ROOT)
    try:
        models = ollama_models(DEFAULT_HOST)
    except OllamaUnavailable as exc:
        print(f"Preflight failed: {exc}\nStart it with: ollama serve")
        return EXIT_PREFLIGHT
    if not model_available(models, args.model):
        print(f"Preflight failed: model {args.model!r} not found (have: {models}).\n"
              f"Fetch it with: ollama pull {args.model}")
        return EXIT_PREFLIGHT
    print(f"Preflight ok: Ollama reachable, model {args.model} present.")
    if args.preflight_only:
        print("No model was run and no files were written.")
        return _isolation_report(before, ROOT)

    sandboxes: list[Path] = []
    status = EXIT_OK
    try:
        runs = 2 if args.drift else 1
        outputs = []
        for index in range(runs):
            sandbox = prepare_sandbox(args.architecture)
            sandboxes.append(sandbox)
            print(f"Run {index + 1}/{runs} in {sandbox} (approaches: {', '.join(approaches)})")
            env = build_env(approaches, args.architecture, args.model)
            proc = run_main(sandbox, env, args.timeout)
            if proc.returncode != 0:
                print(
                    f"main exited with {proc.returncode}.\n"
                    f"{proc.stdout[-800:]}\n{proc.stderr[-1500:]}"
                )
                status = EXIT_CHECK_FAILED
                break
            outputs.append(sandbox)

        if outputs:
            failures, warnings = check_outputs(
                outputs[0], approaches, args.architecture, args.model
            )
            for w in warnings:
                print(f"WARNING: {w}")
            for f in failures:
                print(f"FAIL: {f}")
            print("Checks passed." if not failures else f"{len(failures)} check(s) failed.")
            if failures:
                status = EXIT_CHECK_FAILED
            if args.drift and len(outputs) == 2:
                first, second = load_run_predictions(outputs[0]), load_run_predictions(outputs[1])
                for name in first:
                    same = first[name] == second.get(name)
                    print(f"Drift {name}: predictions {'identical' if same else 'DIFFER'} "
                          "between the two runs (informational)")
    finally:
        if args.keep:
            print("Sandboxes kept: " + ", ".join(map(str, sandboxes)))
        else:
            for sandbox in sandboxes:
                shutil.rmtree(sandbox, ignore_errors=True)

    isolation = _isolation_report(before, ROOT)
    return isolation if isolation != EXIT_OK else status


if __name__ == "__main__":
    sys.exit(main())

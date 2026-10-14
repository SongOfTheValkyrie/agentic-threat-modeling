import json
import urllib.error
import urllib.request
from typing import Protocol, runtime_checkable


@runtime_checkable
class LLMClient(Protocol):
    """Minimal text-in / text-out contract for a language model.

    Kept deliberately small so the model provider is an interchangeable
    variable: a local Ollama model, Ollama Cloud, or any other backend can
    implement this without the RAG pipeline changing.
    """

    name: str

    def complete(self, prompt: str, system: str | None = None) -> str:
        """Return the model's text completion for the given prompt."""
        ...

    def chat(self, messages: list[dict]) -> str:
        """Return the model's reply given a list of role/content messages.

        ``messages`` is a list of ``{"role": ..., "content": ...}`` dicts with
        roles "system", "user", and "assistant". Multi-turn agents use this so
        the model sees its own prior actions and tool results as distinct turns
        rather than one flat string.
        """
        ...


class FakeLLMClient:
    """Deterministic stand-in for tests and offline development.

    Returns a canned response (or echoes the prompt), so the full RAG pipeline
    can be exercised without a running model or network access. Records the last
    prompt/system it was called with for assertions in tests.
    """

    name = "fake"

    def __init__(self, response: str = "", responses: list[str] | None = None):
        # `response` is returned by every call; `responses` (if given) is a
        # scripted sequence returned one per call (useful for multi-turn agents).
        self._response = response
        self._responses = list(responses) if responses else None
        self._index = 0
        self.last_prompt: str | None = None
        self.last_system: str | None = None
        self.last_messages: list[dict] | None = None
        # Usage counters (mirrors OllamaClient so modelers can read them).
        self.llm_calls = 0
        self.tokens = 0

    def _next(self) -> str:
        self.llm_calls += 1
        if self._responses is None:
            return self._response
        value = self._responses[min(self._index, len(self._responses) - 1)]
        self._index += 1
        return value

    def complete(self, prompt: str, system: str | None = None) -> str:
        self.last_prompt = prompt
        self.last_system = system
        return self._next()

    def chat(self, messages: list[dict]) -> str:
        self.last_messages = messages
        return self._next()


class OllamaClient:
    """LLMClient backed by an Ollama server (local or Ollama Cloud).

    Uses Ollama's /api/generate endpoint over HTTP via the standard library, so
    no extra dependency is required. The same client works against a local
    daemon or a cloud endpoint by changing ``host``.
    """

    def __init__(
        self,
        model: str = "llama3.1:8b",
        host: str = "http://localhost:11434",
        timeout: float = 120.0,
    ):
        self.model = model
        self.name = f"ollama:{model}"
        self._host = host.rstrip("/")
        self._timeout = timeout
        # Usage counters, accumulated across calls. A modeler can snapshot these
        # before/after analyze() to log per-run LLM calls and token usage.
        self.llm_calls = 0
        self.tokens = 0

    def _post(self, endpoint: str, payload: dict) -> dict:
        # Low temperature: we want consistent, structured output, not creative
        # variation.
        payload = {"model": self.model, "stream": False,
                   "options": {"temperature": 0.0}, **payload}
        request = urllib.request.Request(
            f"{self._host}/{endpoint}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self._timeout) as response:
                body = json.loads(response.read().decode("utf-8"))
        except urllib.error.URLError as exc:
            raise RuntimeError(
                f"Could not reach Ollama at {self._host}. Is the server running? ({exc})"
            ) from exc

        self.llm_calls += 1
        self.tokens += int(body.get("prompt_eval_count", 0)) + int(
            body.get("eval_count", 0)
        )
        return body

    def complete(self, prompt: str, system: str | None = None) -> str:
        payload: dict = {"prompt": prompt}
        if system is not None:
            payload["system"] = system
        return self._post("api/generate", payload).get("response", "")

    def chat(self, messages: list[dict]) -> str:
        body = self._post("api/chat", {"messages": messages})
        return body.get("message", {}).get("content", "")

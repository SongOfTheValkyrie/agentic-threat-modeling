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


class FakeLLMClient:
    """Deterministic stand-in for tests and offline development.

    Returns a canned response (or echoes the prompt), so the full RAG pipeline
    can be exercised without a running model or network access. Records the last
    prompt/system it was called with for assertions in tests.
    """

    name = "fake"

    def __init__(self, response: str = ""):
        self._response = response
        self.last_prompt: str | None = None
        self.last_system: str | None = None

    def complete(self, prompt: str, system: str | None = None) -> str:
        self.last_prompt = prompt
        self.last_system = system
        return self._response


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

    def complete(self, prompt: str, system: str | None = None) -> str:
        payload: dict = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            # Low temperature: we want consistent, structured output, not
            # creative variation.
            "options": {"temperature": 0.0},
        }
        if system is not None:
            payload["system"] = system

        request = urllib.request.Request(
            f"{self._host}/api/generate",
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

        return body.get("response", "")

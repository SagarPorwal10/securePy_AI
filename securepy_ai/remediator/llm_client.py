import json
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict


class LLMClientError(Exception):
    """
    Raised when the LLM client fails to generate a response.
    """


@dataclass
class LLMResponse:
    """
    Represents a response from an LLM.
    """

    model: str
    text: str
    latency_ms: float
    raw: Dict[str, Any]


class BaseLLMClient(ABC):
    """
    Abstract base class for LLM clients.
    """

    @abstractmethod
    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        pass

    def is_available(self) -> bool:
        return True


class OllamaClient(BaseLLMClient):
    """
    Client for interacting with a local Ollama server.

    Default endpoint:
        http://127.0.0.1:11434
    """

    def __init__(
        self,
        model: str = "codellama:13b",
        base_url: str = "http://127.0.0.1:11434",
        timeout: int = 180,
    ):
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

    def is_available(self) -> bool:
        """
        Checks whether the Ollama server is reachable.
        """
        url = f"{self.base_url}/api/tags"

        try:
            with urllib.request.urlopen(url, timeout=5) as response:
                return response.status == 200
        except Exception:
            return False

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        """
        Sends a chat completion request to Ollama.
        """
        payload = {
            "model": self.model,
            "stream": False,
            "messages": [
                {
                    "role": "system",
                    "content": system_prompt,
                },
                {
                    "role": "user",
                    "content": user_prompt,
                },
            ],
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens,
            },
        }

        data = json.dumps(payload).encode("utf-8")

        request = urllib.request.Request(
            url=f"{self.base_url}/api/chat",
            data=data,
            headers={
                "Content-Type": "application/json",
            },
            method="POST",
        )

        start_time = time.perf_counter()

        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read().decode("utf-8")
        except urllib.error.HTTPError as exc:
            raise LLMClientError(
                f"Ollama HTTP error {exc.code}: {exc.reason}"
            ) from exc
        except urllib.error.URLError as exc:
            raise LLMClientError(
                f"Cannot connect to Ollama at {self.base_url}. "
                f"Is Ollama running? Details: {exc.reason}"
            ) from exc
        except TimeoutError as exc:
            raise LLMClientError(
                f"Ollama request timed out after {self.timeout} seconds."
            ) from exc

        latency_ms = (time.perf_counter() - start_time) * 1000

        try:
            response_json = json.loads(body)
        except json.JSONDecodeError as exc:
            raise LLMClientError("Ollama returned invalid JSON.") from exc

        text = response_json.get("message", {}).get("content", "")

        if not text:
            raise LLMClientError("Ollama returned an empty response.")

        return LLMResponse(
            model=self.model,
            text=text,
            latency_ms=latency_ms,
            raw=response_json,
        )


class MockLLMClient(BaseLLMClient):
    """
    Mock LLM client for offline testing and CI demos.

    This allows SecurePy AI to be tested without installing Ollama
    or downloading large models.
    """

    def __init__(self, model: str = "mock-llm"):
        self.model = model

    def generate(
        self,
        system_prompt: str,
        user_prompt: str,
        temperature: float = 0.1,
        max_tokens: int = 2048,
    ) -> LLMResponse:
        start_time = time.perf_counter()

        text = """```python
# SecurePy AI mock patch
def securepy_mock_fix():
    # Replace with validated secure implementation.
    return None
```"""

        latency_ms = (time.perf_counter() - start_time) * 1000

        return LLMResponse(
            model=self.model,
            text=text,
            latency_ms=latency_ms,
            raw={
                "mock": True,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
        )

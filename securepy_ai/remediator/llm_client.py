import json
import time
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional

from securepy_ai.remediator.ollama_config import OllamaConfig


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
    Client for interacting with an Ollama server (local or remote).

    Accepts either an ``OllamaConfig`` object **or** the legacy keyword
    arguments (``model``, ``base_url``, ``timeout``) for backwards
    compatibility.  When both are supplied, explicit kwargs win.

    Recommended usage (picks up .env / environment variables):
        config = OllamaConfig.from_env()
        client = OllamaClient(config=config)

    Legacy usage (still works):
        client = OllamaClient(model="codellama:13b", base_url="http://127.0.0.1:11434")
    """

    def __init__(
        self,
        model: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[int] = None,
        config: Optional[OllamaConfig] = None,
    ):
        # Resolve from config first, then allow explicit kwargs to override.
        _config = config or OllamaConfig.from_env()

        self.model    = model    or _config.model
        self.base_url = (base_url or _config.base_url).rstrip("/")
        self.timeout  = timeout  if timeout is not None else _config.timeout

        # Expose the resolved config for introspection / display.
        self.config = _config

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

    Each rule gets a realistic, rule-appropriate mock patch so the
    PatchValidator can mark it as "vuln_fixed" during demo runs.
    """

    # Mapping from rule ID to a representative secure replacement snippet.
    _MOCK_PATCHES: Dict[str, str] = {
        "SEC101": (
            "```python\n"
            "import os\n\n"
            "# SecurePy AI mock patch: move secret to environment variable\n"
            "secret = os.environ.get('SECRET_KEY')\n"
            "if secret is None:\n"
            "    raise EnvironmentError('SECRET_KEY environment variable is not set')\n"
            "```"
        ),
        "SEC102": (
            "```python\n"
            "# SecurePy AI mock patch: use parameterised query\n"
            "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))\n"
            "```"
        ),
        "SEC103": (
            "```python\n"
            "import subprocess\n\n"
            "# SecurePy AI mock patch: use subprocess with argument list, shell=False\n"
            "subprocess.run(['ls', '-la'], shell=False, check=True)\n"
            "```"
        ),
        "SEC104": (
            "```python\n"
            "import json\n\n"
            "# SecurePy AI mock patch: replace pickle/yaml.load with safe json.loads\n"
            "data = json.loads(raw_input)\n"
            "```"
        ),
        "SEC105": (
            "```python\n"
            "# SecurePy AI mock patch: replace eval with ast.literal_eval\n"
            "import ast\n"
            "result = ast.literal_eval(user_input)\n"
            "```"
        ),
    }

    # CWE ID → rule ID mapping so prompts that include CWE but not rule ID still match.
    _CWE_TO_RULE: Dict[str, str] = {
        "CWE-798": "SEC101",
        "CWE-89":  "SEC102",
        "CWE-78":  "SEC103",
        "CWE-502": "SEC104",
        "CWE-95":  "SEC105",
    }

    _DEFAULT_PATCH = (
        "```python\n"
        "# SecurePy AI mock patch — apply secure coding best practices here\n"
        "pass\n"
        "```"
    )

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

        # Detect which rule is being fixed — check for rule ID first,
        # then fall back to CWE ID (PromptBuilder includes CWE but not rule ID).
        text = self._DEFAULT_PATCH
        for rule_id, patch_text in self._MOCK_PATCHES.items():
            if rule_id in user_prompt:
                text = patch_text
                break
        else:
            for cwe_id, rule_id in self._CWE_TO_RULE.items():
                if cwe_id in user_prompt:
                    text = self._MOCK_PATCHES[rule_id]
                    break


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


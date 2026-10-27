"""Optional real-LLM adapter interface. NOT IMPLEMENTED and NOT RUN in this repository.

A real-model experiment is a *separate* experiment: results must go to results/llm-optional/ and must never be
mixed with the deterministic scripted-trace results. It would need an API key, costs money, and is non-deterministic.
"""
from __future__ import annotations

from typing import Any, Protocol


class LLMAdapter(Protocol):
    def propose(self, task: str, observations: list[str]) -> dict[str, Any]:
        """Return the next tool-call proposal: {'tool': str, 'params': dict}."""
        ...


class NotConfigured:
    def propose(self, task: str, observations: list[str]) -> dict[str, Any]:
        raise NotImplementedError("No LLM adapter is configured; the repository ships deterministic traces only.")

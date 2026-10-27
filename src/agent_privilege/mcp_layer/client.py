"""MCP client used only by the gateway. Supports in-memory transport (fast, used by the
evaluator) and real stdio subprocess transport (used by integration tests/latency)."""
from __future__ import annotations

import json
import sys
from contextlib import AsyncExitStack
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from mcp.shared.memory import create_connected_server_and_client_session

from .server import build_server


class McpBankingClient:
    def __init__(self) -> None:
        self._stack = AsyncExitStack()
        self.session: ClientSession | None = None

    async def connect_memory(self, service) -> McpBankingClient:
        server = build_server(service)
        self.session = await self._stack.enter_async_context(
            create_connected_server_and_client_session(server._mcp_server))
        return self

    async def connect_stdio(self, env: dict[str, str]) -> McpBankingClient:
        params = StdioServerParameters(command=sys.executable, args=["-m", "agent_privilege.mcp_layer.server"],
                                       env=env)
        r, w = await self._stack.enter_async_context(stdio_client(params))
        self.session = await self._stack.enter_async_context(ClientSession(r, w))
        await self.session.initialize()
        return self

    async def call(self, tool: str, params: dict[str, Any], request_hash: str,
                   assertion: str) -> dict[str, Any]:
        assert self.session is not None
        res = await self.session.call_tool(tool, {**params, "request_hash": request_hash,
                                                  "assertion": assertion})
        text = "".join(getattr(c, "text", "") for c in res.content)
        return json.loads(text)

    async def list_tools(self) -> list[str]:
        assert self.session is not None
        return sorted(t.name for t in (await self.session.list_tools()).tools)

    async def close(self) -> None:
        await self._stack.aclose()

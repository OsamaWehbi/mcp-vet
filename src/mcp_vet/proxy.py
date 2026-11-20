"""A stdio proxy that sits between an MCP client and a server and applies `RuntimeInspector`.

The client starts `mcp-vet proxy -- <server command>` instead of the server. The proxy starts the
server, relays newline-delimited JSON-RPC in both directions and lets the inspector rewrite or refuse
messages. Messages the inspector does not change are forwarded byte for byte. The server's stderr is
passed through, and the proxy's own log lines also go to stderr, which MCP reserves for logging.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # nosec B404
from collections.abc import AsyncIterator
from typing import Any, BinaryIO

import anyio
from anyio.abc import ByteReceiveStream

from mcp_vet.runtime import RuntimeInspector, dumps

MAX_MESSAGE_BYTES = 64 * 1024 * 1024
SHUTDOWN_GRACE = 10.0
_INVALID = object()
# subprocess above is imported only for its PIPE constant; anyio starts the server process.


class ProxyError(Exception):
    pass


def resolve_command(command: list[str]) -> list[str]:
    """Resolve the executable on PATH (this also finds npx.cmd and similar on Windows)."""
    if not command:
        raise ProxyError("no server command given; put it after --, e.g. mcp-vet proxy -- npx -y some-server")
    exe = shutil.which(command[0])
    if exe is None:
        raise ProxyError(f"command not found: {command[0]}")
    return [exe, *command[1:]]


def _parse(line: bytes) -> Any:
    try:
        return json.loads(line)
    except ValueError:
        return _INVALID


async def _lines(stream: ByteReceiveStream) -> AsyncIterator[bytes]:
    buf = bytearray()
    async for chunk in stream:
        start = len(buf)
        buf += chunk
        while (i := buf.find(b"\n", start)) >= 0:
            yield bytes(buf[:i])
            del buf[: i + 1]
            start = 0
        if len(buf) > MAX_MESSAGE_BYTES:
            raise ProxyError(f"server sent a message larger than {MAX_MESSAGE_BYTES // (1024 * 1024)} MB")
    if buf.strip():
        yield bytes(buf)


def _write(stream: BinaryIO, data: bytes) -> None:
    stream.write(data + b"\n")
    stream.flush()


async def run_proxy(command: list[str], inspector: RuntimeInspector, stdin: BinaryIO, stdout: BinaryIO) -> int:
    """Relay traffic until the server exits. Returns the server's exit code."""
    try:
        process = await anyio.open_process(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=None)
    except OSError as exc:
        raise ProxyError(f"could not start {command[0]}: {exc}") from exc

    async with process:
        # Both streams exist because they were requested with PIPE above.
        assert process.stdin is not None and process.stdout is not None  # nosec B101
        server_in, server_out = process.stdin, process.stdout

        async def client_to_server() -> None:
            while True:
                line = await anyio.to_thread.run_sync(stdin.readline, abandon_on_cancel=True)
                if not line:
                    break
                body = line.rstrip(b"\r\n")
                if not body.strip():
                    continue
                message = _parse(body)
                if message is _INVALID:
                    forward: bytes | None = body
                else:
                    decision = inspector.from_client(message)
                    for reply in decision.replies:
                        _write(stdout, dumps(reply))
                    if decision.forward is None:
                        forward = None
                    elif decision.forward is message:
                        forward = body
                    else:
                        forward = dumps(decision.forward)
                if forward is not None:
                    try:
                        await server_in.send(forward + b"\n")
                    except (anyio.BrokenResourceError, anyio.ClosedResourceError):
                        break
            # The client hung up: close the server's stdin and give it time to exit on its own.
            await server_in.aclose()
            with anyio.move_on_after(SHUTDOWN_GRACE):
                await process.wait()
            if process.returncode is None:
                process.terminate()

        async with anyio.create_task_group() as tg:
            tg.start_soon(client_to_server)
            async for line in _lines(server_out):
                message = _parse(line)
                replacement = None if message is _INVALID else inspector.from_server(message)
                _write(stdout, line if replacement is None else dumps(replacement))
            tg.cancel_scope.cancel()
        return await process.wait()

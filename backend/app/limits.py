from __future__ import annotations

import os
from collections import deque
from collections.abc import Awaitable, Callable
from typing import Any

from starlette.responses import JSONResponse

DEFAULT_IMPORT_REQUEST_BYTES = 12 * 1024 * 1024


def positive_int_setting(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default
    return value if value > 0 else default


class RequestBodyLimitMiddleware:
    """Reject oversized scan requests before JSON validation allocates them."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(
        self,
        scope: dict[str, Any],
        receive: Callable[[], Awaitable[dict[str, Any]]],
        send: Callable[[dict[str, Any]], Awaitable[None]],
    ) -> None:
        if scope.get("type") != "http" or scope.get("path") != "/import/scan":
            await self.app(scope, receive, send)
            return

        limit = positive_int_setting(
            "MAX_IMPORT_REQUEST_BYTES", DEFAULT_IMPORT_REQUEST_BYTES
        )
        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        content_length = headers.get(b"content-length")
        if content_length:
            if not content_length.isdigit():
                response = JSONResponse(
                    {"detail": "Invalid Content-Length header"}, status_code=400
                )
                await response(scope, receive, send)
                return
            declared_length = int(content_length)
            if declared_length > limit:
                response = JSONResponse(
                    {"detail": f"Import request exceeds the {limit}-byte limit"},
                    status_code=413,
                )
                await response(scope, receive, send)
                return

        received = 0
        buffered_messages: deque[dict[str, Any]] = deque()
        more_body = True
        while more_body:
            message = await receive()
            buffered_messages.append(message)
            if message.get("type") == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    response = JSONResponse(
                        {"detail": f"Import request exceeds the {limit}-byte limit"},
                        status_code=413,
                    )
                    await response(scope, receive, send)
                    return
                more_body = bool(message.get("more_body", False))
            elif message.get("type") == "http.disconnect":
                return

        async def replay_receive() -> dict[str, Any]:
            if buffered_messages:
                return buffered_messages.popleft()
            return await receive()

        await self.app(scope, replay_receive, send)

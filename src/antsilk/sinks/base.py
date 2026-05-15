from __future__ import annotations

from typing import Protocol, runtime_checkable

from antsilk.events import Event


@runtime_checkable
class EventSink(Protocol):
    """Sync interface every event-logging backend implements.

    Middleware invokes sinks via ``asyncio.to_thread`` so blocking I/O
    here does not stall the event loop. Implementations should treat
    ``write`` as fire-and-forget for the caller's purposes — return
    once the event is durable, raise on hard failures (the middleware
    catches and logs).
    """

    def write(self, event: Event) -> None: ...

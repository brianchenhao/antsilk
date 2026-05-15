from __future__ import annotations

from antsilk.events import Event


class RemoteSink:
    """v0.1.0 stub for a future HTTP-based event forwarder.

    Constructing the sink succeeds so adopters can reference it in
    config code today without breaking imports. Calling ``write()``
    raises ``NotImplementedError`` with a pointer to the v0.5.0
    milestone where real transport lands.
    """

    def __init__(
        self, endpoint: str, *, api_key: str | None = None
    ) -> None:
        self.endpoint = endpoint
        self.api_key = api_key

    def write(self, event: Event) -> None:
        del event
        raise NotImplementedError(
            "RemoteSink is a v0.1.0 stub — real HTTP forwarding lands in"
            " v0.5.0. Use SQLiteSink or JSONLinesSink for now."
        )

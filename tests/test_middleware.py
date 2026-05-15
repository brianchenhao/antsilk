from __future__ import annotations

from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import AntsilkConfig, AntsilkMiddleware


def test_middleware_passes_request_through(client: TestClient) -> None:
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_middleware_returns_429_when_rate_limit_exceeded() -> None:
    app = FastAPI()
    app.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(requests_per_minute=3, threat_intel_enabled=False),
    )

    @app.get("/")
    async def root() -> dict[str, bool]:
        return {"ok": True}

    client = TestClient(app)
    for _ in range(3):
        assert client.get("/").status_code == 200

    response = client.get("/")
    assert response.status_code == 429
    assert response.json() == {"error": "rate_limited"}
    assert response.headers["retry-after"] == "60"
    assert response.headers["content-type"] == "application/json"

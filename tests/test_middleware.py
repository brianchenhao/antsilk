from __future__ import annotations

from fastapi.testclient import TestClient


def test_middleware_passes_request_through(client: TestClient) -> None:
    response = client.get("/ping")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}

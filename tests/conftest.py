from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import AntsilkConfig, AntsilkMiddleware


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    # Disable threat-intel in the shared fixture so the background fetch
    # task never spawns real network requests against FireHOL / Spamhaus
    # during unrelated tests. Tests focused on threat-intel build their
    # own app with the rule enabled and a pre-populated store.
    application.add_middleware(
        AntsilkMiddleware,
        config=AntsilkConfig(threat_intel_enabled=False),
    )

    @application.get("/ping")
    async def ping() -> dict[str, str]:
        return {"status": "ok"}

    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)

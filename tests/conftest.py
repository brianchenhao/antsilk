from __future__ import annotations

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from antsilk import AntsilkMiddleware


@pytest.fixture
def app() -> FastAPI:
    application = FastAPI()
    application.add_middleware(AntsilkMiddleware)

    @application.get("/ping")
    async def ping() -> dict[str, str]:
        return {"status": "ok"}

    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)

"""Minimal FastAPI app showing the two-line antsilk install.

Run with:
    pip install antsilk fastapi 'uvicorn[standard]'
    uvicorn examples.fastapi_demo:app --reload
"""

from __future__ import annotations

from fastapi import FastAPI

from antsilk import AntsilkMiddleware

app = FastAPI(title="antsilk demo")
app.add_middleware(AntsilkMiddleware)


@app.get("/")
async def root() -> dict[str, str]:
    return {"message": "hello from antsilk demo"}


@app.get("/items/{item_id}")
async def read_item(item_id: int) -> dict[str, int]:
    return {"item_id": item_id}


@app.post("/echo")
async def echo(payload: dict) -> dict:
    return {"received": payload}

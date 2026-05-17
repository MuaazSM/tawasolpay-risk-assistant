"""FastAPI application entry point.

Endpoints: GET /health, GET /risks/top, GET /risk/{asset_id}/{vuln_id},
POST /refresh. On startup, runs the pipeline once and caches results
in memory. CORS configured via CORS_ORIGIN env var.
"""

from fastapi import FastAPI

app = FastAPI(title="TawasolPay Cyber Risk Assistant")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}

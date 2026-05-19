"""FastAPI application entry point."""

from __future__ import annotations

import asyncio
import logging
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.routes import router
from src.pipeline import run_pipeline

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    stream=sys.stderr,
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize pipeline state on startup.

    Runs the full pipeline once, caches results and a lookup index on
    app.state. If the pipeline fails, the exception is logged and
    re-raised so the process exits with a non-zero code. Render (or
    any process supervisor) will see the failed startup and stop the
    deploy.
    """
    app.state.pipeline_results = None
    app.state.risk_index = {}
    app.state.last_refresh = None
    app.state.refresh_lock = asyncio.Lock()

    try:
        # use_cache=True so enrichment is persisted for later light refreshes
        results = run_pipeline(top_k=5, use_cache=True)
        app.state.pipeline_results = results
        app.state.risk_index = {
            (r.asset_id, r.vuln_id): r for r in results
        }
        app.state.last_refresh = datetime.now(timezone.utc)
        logger.info(
            "startup: pipeline ready, %d risks cached", len(results),
        )
    except Exception:
        logger.exception("startup: pipeline failed, aborting")
        raise

    yield


app = FastAPI(
    title="TawasolPay Cyber Risk Assistant",
    description=(
        "Top-5 cyber risk ranking for a fictional fintech, combining "
        "structured vulnerability data with NIST 800-53 control retrieval."
    ),
    version="0.1.0",
    lifespan=lifespan,
)

_cors_raw = os.environ.get("CORS_ORIGIN", "http://localhost:3000")
_cors_origins = [o.strip() for o in _cors_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_methods=["GET", "POST"],
    allow_credentials=True,
    allow_headers=["*"],
)

app.include_router(router)

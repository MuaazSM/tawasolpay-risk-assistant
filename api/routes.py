"""API route definitions.

GET  /health                  — Level 2 health: status, pipeline readiness,
                                risk count, last refresh timestamp.
GET  /risks/top?k=5           — Return top-k ranked risks with explanations.
GET  /risk/{asset_id}/{vuln_id} — Return a single risk detail.
POST /refresh                 — Light refresh: re-score cached enriched data
                                without re-fetching external sources (CISA KEV,
                                threat intel CSVs, threat report). Returns 409
                                if a refresh is already in progress.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from src.pipeline import run_pipeline
from src.schemas import TopRiskOutput

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# Dependency: typed accessor with 503 guard
# ---------------------------------------------------------------------------


def get_pipeline_results(request: Request) -> list[TopRiskOutput]:
    """Return cached pipeline results or 503 if the pipeline hasn't run yet.

    Used as a FastAPI dependency so every endpoint that needs results gets
    a consistent guard without duplicating the check.
    """
    results = request.app.state.pipeline_results
    if results is None:
        raise HTTPException(
            status_code=503,
            detail="Pipeline not ready — startup may still be in progress",
        )
    return results


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/health")
async def health(request: Request) -> dict:
    """Level 2 health check with pipeline metadata.

    Always returns 200 — use pipeline_ready to distinguish between a
    healthy server that's still initializing and one that's fully ready.
    """
    ready = request.app.state.pipeline_results is not None
    return {
        "status": "ok",
        "pipeline_ready": ready,
        "risk_count": len(request.app.state.pipeline_results) if ready else 0,
        "last_refresh": (
            request.app.state.last_refresh.isoformat()
            if request.app.state.last_refresh
            else None
        ),
    }


@router.get("/risks/top", response_model=list[TopRiskOutput])
async def get_top_risks(
    results: list[TopRiskOutput] = Depends(get_pipeline_results),
    k: int = Query(default=5, ge=1, le=50),
) -> list[TopRiskOutput]:
    """Return the top-k ranked cyber risks with full explanations.

    Args:
        k: Number of risks to return (1-50, default 5). If k exceeds the
           number of available results, returns all available.
    """
    return results[:k]


@router.get("/risk/{asset_id}/{vuln_id}", response_model=TopRiskOutput)
async def get_risk(
    asset_id: str,
    vuln_id: str,
    request: Request,
    _results: list[TopRiskOutput] = Depends(get_pipeline_results),
) -> TopRiskOutput:
    """Return a single risk by its (asset_id, vuln_id) composite key.

    Raises:
        404 if the risk is not in the current top-k set.
    """
    risk = request.app.state.risk_index.get((asset_id, vuln_id))
    if risk is None:
        raise HTTPException(
            status_code=404,
            detail=f"Risk not found: {asset_id}/{vuln_id}",
        )
    return risk


@router.post("/refresh")
async def refresh(request: Request) -> dict:
    """Light refresh: re-score cached enriched data.

    Re-runs scoring, NIST retrieval, and explanation generation on the
    previously cached enriched DataFrame. Does NOT re-fetch external data
    sources (CISA KEV catalog, threat intel CSVs, MDR threat report).
    Use this after a scoring formula change or to regenerate explanations.

    For a full pipeline refresh that re-ingests all external sources,
    redeploy the service (the startup handler runs the full pipeline).

    Returns 409 if another refresh is already in progress.
    Returns 503 if no enriched cache exists (full pipeline never ran).
    """
    lock: asyncio.Lock = request.app.state.refresh_lock

    # asyncio is single-threaded — no race between locked() check and acquire
    if lock.locked():
        raise HTTPException(
            status_code=409,
            detail="Refresh already in progress",
        )

    async with lock:
        logger.info("refresh: starting light refresh")
        try:
            results = await asyncio.to_thread(
                run_pipeline, top_k=5, light_refresh=True,
            )
        except ValueError as exc:
            # light_refresh raises ValueError when enriched cache is missing
            raise HTTPException(status_code=503, detail=str(exc)) from exc

        request.app.state.pipeline_results = results
        request.app.state.risk_index = {
            (r.asset_id, r.vuln_id): r for r in results
        }
        request.app.state.last_refresh = datetime.now(timezone.utc)
        logger.info("refresh: complete — %d risks updated", len(results))

    return {
        "status": "refreshed",
        "risk_count": len(results),
        "last_refresh": request.app.state.last_refresh.isoformat(),
    }

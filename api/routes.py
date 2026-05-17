"""API route definitions.

GET /risks/top?k=5 — return top-k ranked risks with explanations.
GET /risk/{asset_id}/{vuln_id} — return a single risk detail.
POST /refresh — re-run the pipeline and update cached results.
"""

from fastapi import APIRouter

router = APIRouter()

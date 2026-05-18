"""Retrieve NIST 800-53 controls for a given enriched risk.

Entry point: retrieve_controls_for_risk(risk, k) -> list[NistControl]

Uses a two-query strategy — all deterministic, no LLM involvement:

1. Primary query: built from vulnerability description, asset type, asset
   name, campaign names, and missing-control keywords. Captures full context
   but uses vendor/exploit vocabulary that may not match NIST prose.
2. Focused query: short, uses only NIST vocabulary (e.g., "identify and
   authenticate organizational users" for auth bypass risks). Targets the
   correct base controls that the primary query misses due to vocabulary gap.

Results from both queries are combined via round-robin interleave with a
small family-boost (+0.03 similarity) for controls whose NIST family aligns
with the risk's keywords. Family boost reranks within close-similarity
matches; without it, the same controls appear in top-5 but in slightly
different order for ~1/3 of risk types. Kept because the cost is trivial
and the rank improvement is visible in golden tests (e.g., promotes CM-8.2
for stale-asset risks).
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

from src.schemas import EnrichedRisk, NistControl

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CHROMA_PATH = _PROJECT_ROOT / "data" / "processed" / "nist_chroma"
_COLLECTION_NAME = "nist_800_53_r5"
_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"

# ---------------------------------------------------------------------------
# Family-boost mapping
# ---------------------------------------------------------------------------
# Maps keywords (found in vulnerability description or asset type) to NIST
# control families that are especially relevant. The boost is additive to
# the similarity score (Chroma returns cosine distance; lower = closer).
# We convert distance to similarity (1 - distance) so higher = better,
# then add the boost.

_FAMILY_BOOST_AMOUNT = 0.03  # small enough to rerank within close scores, not override semantic match

_KEYWORD_TO_FAMILIES: dict[str, list[str]] = {
    "authentication": ["Access Control", "Identification and Authentication"],
    "auth bypass": ["Access Control", "Identification and Authentication"],
    "auth": ["Access Control", "Identification and Authentication"],
    "credential": ["Identification and Authentication"],
    "password": ["Identification and Authentication"],
    "login": ["Identification and Authentication"],
    "privilege escalation": ["Access Control"],
    "access control": ["Access Control"],
    "authorization": ["Access Control"],
    "injection": ["System and Information Integrity", "System and Communications Protection"],
    "sql injection": ["System and Information Integrity"],
    "xss": ["System and Information Integrity"],
    "cross-site": ["System and Information Integrity"],
    "remote code execution": ["System and Information Integrity"],
    "rce": ["System and Information Integrity"],
    "overflow": ["System and Information Integrity"],
    "patch": ["System and Information Integrity"],
    "unpatched": ["System and Information Integrity"],
    "update": ["System and Information Integrity"],
    "configuration": ["Configuration Management"],
    "misconfiguration": ["Configuration Management"],
    "hardening": ["Configuration Management"],
    "ci/cd": ["Configuration Management", "Supply Chain Risk Management"],
    "pipeline": ["Configuration Management", "Supply Chain Risk Management"],
    "supply chain": ["Supply Chain Risk Management"],
    "encryption": ["System and Communications Protection"],
    "tls": ["System and Communications Protection"],
    "ssl": ["System and Communications Protection"],
    "vpn": ["Access Control", "System and Communications Protection"],
    "firewall": ["System and Communications Protection"],
    "network": ["System and Communications Protection"],
    "monitoring": ["Audit and Accountability", "System and Information Integrity"],
    "logging": ["Audit and Accountability"],
    "audit": ["Audit and Accountability"],
    "edr": ["System and Information Integrity"],
    "malware": ["System and Information Integrity"],
    "ransomware": ["System and Information Integrity", "Contingency Planning"],
    "backup": ["Contingency Planning"],
    "recovery": ["Contingency Planning"],
    "asset": ["Configuration Management"],
    "inventory": ["Configuration Management"],
    "stale": ["Configuration Management"],
}

# ---------------------------------------------------------------------------
# Singleton loaders — embedding model and Chroma collection
# ---------------------------------------------------------------------------

_model: SentenceTransformer | None = None
_collection: chromadb.Collection | None = None


def _get_embedding_model() -> SentenceTransformer:
    """Load the embedding model once and cache it."""
    global _model
    if _model is None:
        logger.info("Loading embedding model %s", _EMBEDDING_MODEL)
        _model = SentenceTransformer(_EMBEDDING_MODEL)
    return _model


def _get_collection() -> chromadb.Collection:
    """Open the persisted Chroma collection."""
    global _collection
    if _collection is None:
        if not _CHROMA_PATH.exists():
            raise FileNotFoundError(
                f"Chroma index not found at {_CHROMA_PATH}. "
                "Run scripts/build_nist_index.py first."
            )
        client = chromadb.PersistentClient(path=str(_CHROMA_PATH))
        _collection = client.get_collection(_COLLECTION_NAME)
        logger.info(
            "Loaded Chroma collection '%s' with %d controls",
            _COLLECTION_NAME,
            _collection.count(),
        )
    return _collection


# ---------------------------------------------------------------------------
# Query construction — deterministic, no LLM
# ---------------------------------------------------------------------------


def build_query(risk: EnrichedRisk) -> str:
    """Build the primary retrieval query from risk fields.

    Combines vulnerability description, asset type, asset name, and campaign
    names. This query captures the full context of the risk but uses
    vendor/exploit vocabulary that may not align with NIST's regulatory prose.

    A separate focused query (build_focused_query) uses only NIST vocabulary
    to ensure base controls like IA-2 and SI-2 aren't drowned out by
    Fortinet-specific jargon.
    """
    parts: list[str] = []

    if risk.description:
        parts.append(risk.description)

    if risk.asset_type:
        parts.append(risk.asset_type)
    if risk.asset_name:
        parts.append(risk.asset_name)

    for campaign in risk.campaign_matches:
        parts.append(campaign)

    # missing controls hint at what's needed
    _control_gap_keywords = {
        "no_edr": "endpoint detection response",
        "no_mfa": "multi-factor authentication",
        "stale_asset": "asset inventory management",
        "no_owner": "asset ownership accountability",
        "no_patching": "patch management vulnerability remediation",
        "no_encryption": "encryption data protection",
        "no_logging": "audit logging monitoring",
    }
    for gap in risk.missing_controls:
        keyword = _control_gap_keywords.get(gap)
        if keyword:
            parts.append(keyword)

    if risk.internet_exposed == "Yes":
        parts.append("remote access")

    query = " ".join(parts)
    if not query.strip():
        query = f"{risk.cve_id} {risk.severity} vulnerability"

    logger.debug("Built primary query: %s", query)
    return query


# Vulnerability-type → NIST vocabulary mappings. Each entry produces a short
# query using only the terms NIST uses in the relevant control's statement
# or discussion. Kept separate from the primary query so vendor jargon
# (e.g., "Fortinet", "SSL-VPN") doesn't dilute the NIST-specific signal.
_VULN_TYPE_FOCUSED_QUERIES: list[tuple[list[str], str]] = [
    # auth bypass → IA-2 "Identification and Authentication (Organizational
    # Users)": "uniquely identify and authenticate organizational users"
    (
        ["auth bypass", "authentication bypass", "bypass authentication"],
        "identify and authenticate organizational users",
    ),
    # RCE / overflow → SI-2 "Flaw Remediation": "identify report and
    # correct system flaws", "security-relevant software and firmware updates"
    (
        ["remote code execution", "rce", "heap overflow", "buffer overflow",
         "code execution"],
        "flaw remediation identify report correct system flaws "
        "security-relevant software firmware updates",
    ),
    # unpatched / missing patches → SI-2 again
    (
        ["unpatched", "missing patch", "missing security patch"],
        "flaw remediation patch management software updates",
    ),
    # credential leak → IA-5 "Authenticator Management"
    (
        ["credential leak", "credential exposure", "secret exposure",
         "hardcoded credential", "leaked secret"],
        "authenticator management credential protection",
    ),
    # session hijack → SC-23 "Session Authenticity"
    (
        ["session hijack", "session token", "session fixation"],
        "session authenticity session termination",
    ),
    # injection → SI-10 "Information Input Validation"
    (
        ["sql injection", "command injection", "code injection"],
        "information input validation",
    ),
    # XSS → SI-10 + SC-18
    (
        ["cross-site scripting", "xss"],
        "information input validation mobile code",
    ),
]


def build_focused_query(risk: EnrichedRisk) -> str | None:
    """Build a short NIST-vocabulary query for the risk's vulnerability type.

    Returns None if the vulnerability description doesn't match any known
    pattern. When it does match, the returned query uses only NIST prose
    vocabulary — no vendor names, no CVE jargon — so the embedding model
    lands directly on the correct base controls.

    This is the second leg of a two-query retrieval strategy. The primary
    query (build_query) captures full context; this one targets precision.
    """
    desc_lower = risk.description.lower()
    for patterns, focused in _VULN_TYPE_FOCUSED_QUERIES:
        if any(p in desc_lower for p in patterns):
            logger.debug("Built focused query: %s", focused)
            return focused
    return None


# ---------------------------------------------------------------------------
# Family boost logic
# ---------------------------------------------------------------------------


def _compute_family_boosts(risk: EnrichedRisk) -> set[str]:
    """Determine which NIST families deserve a boost for this risk.

    Scans the risk's description, asset_type, and missing_controls for
    keywords that map to specific NIST families.
    """
    boosted_families: set[str] = set()
    # build a single lowercase text blob to search
    text = " ".join([
        risk.description,
        risk.asset_type,
        risk.asset_name,
        " ".join(risk.missing_controls),
    ]).lower()

    for keyword, families in _KEYWORD_TO_FAMILIES.items():
        if keyword in text:
            boosted_families.update(families)

    if boosted_families:
        logger.debug("Family boost applied for: %s", boosted_families)

    return boosted_families


# ---------------------------------------------------------------------------
# Document parsing — extract structured fields from Chroma document text
# ---------------------------------------------------------------------------


def _parse_document(doc: str) -> dict[str, str | list[str]]:
    """Parse a Chroma document back into structured fields.

    The document was stored in the format produced by
    scripts/build_nist_index.py:format_chunk — a newline-separated block
    with labeled fields.
    """
    fields: dict[str, str] = {}
    current_key = ""
    current_lines: list[str] = []

    for line in doc.split("\n"):
        # check if this line starts a new field
        match = re.match(r"^(Control|Name|Family|Statement|Discussion|Related):\s*(.*)", line)
        if match:
            if current_key:
                fields[current_key] = " ".join(current_lines).strip()
            current_key = match.group(1).lower()
            current_lines = [match.group(2)]
        else:
            current_lines.append(line)

    if current_key:
        fields[current_key] = " ".join(current_lines).strip()

    # parse related controls list
    related_str = fields.get("related", "None")
    related: list[str] = []
    if related_str and related_str != "None":
        related = [r.strip() for r in related_str.split(",") if r.strip()]

    return {
        "statement": fields.get("statement", ""),
        "discussion": fields.get("discussion", ""),
        "related_controls": related,
    }


# ---------------------------------------------------------------------------
# Main retrieval entry point
# ---------------------------------------------------------------------------


def _query_chroma(
    collection: chromadb.Collection,
    model: SentenceTransformer,
    query: str,
    n_results: int,
) -> tuple[list[float], list[str], list[dict]]:
    """Run a single Chroma query, return (distances, documents, metadatas)."""
    query_embedding = model.encode(query, normalize_embeddings=True).tolist()
    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=n_results,
        include=["documents", "metadatas", "distances"],
    )
    return results["distances"][0], results["documents"][0], results["metadatas"][0]


def retrieve_controls_for_risk(
    risk: EnrichedRisk, k: int = 3
) -> list[NistControl]:
    """Retrieve the top-k NIST 800-53 controls relevant to a risk.

    Uses a two-query strategy to bridge the vocabulary gap between CVE
    descriptions and NIST control prose:

    1. **Primary query** — full context (description, asset type, campaigns).
       Captures broad relevance but vendor jargon can drown out base controls.
    2. **Focused query** — short, uses only NIST vocabulary (e.g., "identify
       and authenticate organizational users" for auth bypass risks). Ensures
       base controls like IA-2 and SI-2 surface even when the primary query
       is dominated by product-specific terms.

    Results are combined via **round-robin interleave**: we alternate picks
    from each query's ranked list, skipping duplicates. This guarantees both
    queries contribute to the final top-k rather than one dominating by
    virtue of higher absolute similarity scores (focused queries produce
    higher scores because they're shorter and more targeted, but that
    doesn't mean primary-query results are less relevant).

    Family boost (+0.03) is applied within each query's ranking before
    interleaving.

    Args:
        risk: An enriched risk from the scoring pipeline.
        k: Number of controls to return (default 3).

    Returns:
        List of NistControl objects sorted by relevance (best first).
    """
    collection = _get_collection()
    model = _get_embedding_model()

    primary_query = build_query(risk)
    focused_query = build_focused_query(risk)
    boosted_families = _compute_family_boosts(risk)

    def _score_and_rank(
        distances: list[float],
        documents: list[str],
        metadatas: list[dict],
    ) -> list[tuple[float, str, str, dict]]:
        """Score results with family boost, return sorted (score, cid, doc, meta)."""
        scored = []
        for dist, doc, meta in zip(distances, documents, metadatas):
            sim = 1.0 - dist
            if meta.get("family") in boosted_families:
                sim += _FAMILY_BOOST_AMOUNT
            scored.append((sim, meta["control_id"], doc, meta))
        scored.sort(key=lambda x: x[0], reverse=True)
        return scored

    # primary query — over-fetch to give boost room to promote
    primary_n = min(k * 5, collection.count())
    p_distances, p_documents, p_metadatas = _query_chroma(
        collection, model, primary_query, primary_n
    )
    primary_ranked = _score_and_rank(p_distances, p_documents, p_metadatas)

    # focused query (if applicable)
    focused_ranked: list[tuple[float, str, str, dict]] = []
    if focused_query:
        focused_n = min(k * 3, collection.count())
        f_distances, f_documents, f_metadatas = _query_chroma(
            collection, model, focused_query, focused_n
        )
        focused_ranked = _score_and_rank(f_distances, f_documents, f_metadatas)

    # round-robin interleave: alternate picks, skip duplicates.
    # when only one query exists, it fills all slots.
    seen: set[str] = set()
    selected: list[tuple[float, str, str, dict]] = []
    pi, fi = 0, 0

    while len(selected) < k:
        picked = False

        # try primary
        while pi < len(primary_ranked):
            score, cid, doc, meta = primary_ranked[pi]
            pi += 1
            if cid not in seen:
                seen.add(cid)
                selected.append((score, cid, doc, meta))
                picked = True
                break

        if len(selected) >= k:
            break

        # try focused
        while fi < len(focused_ranked):
            score, cid, doc, meta = focused_ranked[fi]
            fi += 1
            if cid not in seen:
                seen.add(cid)
                selected.append((score, cid, doc, meta))
                picked = True
                break

        # if neither list had new controls, we're exhausted
        if not picked:
            break

    controls: list[NistControl] = []
    for score, cid, doc, meta in selected:
        parsed = _parse_document(doc)
        control = NistControl(
            control_id=meta["control_id"],
            title=meta["title"],
            family=meta["family"],
            statement=parsed["statement"],
            discussion=parsed["discussion"],
            related_controls=parsed["related_controls"],
        )
        controls.append(control)
        logger.debug(
            "Retrieved %s (%.3f): %s", control.control_id, score, control.title
        )

    logger.info(
        "Retrieved %d controls for %s on %s: %s",
        len(controls),
        risk.cve_id,
        risk.asset_name,
        [c.control_id for c in controls],
    )
    return controls

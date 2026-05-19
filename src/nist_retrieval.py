"""Retrieve NIST 800-53 controls for a given enriched risk.

Two-query strategy (primary + focused) with round-robin interleave
and family-boost reranking. All deterministic, no LLM involvement.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path

import numpy as np

import chromadb

from src.schemas import EnrichedRisk, NistControl

logger = logging.getLogger(__name__)

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_CHROMA_PATH = _PROJECT_ROOT / "data" / "processed" / "nist_chroma"
_COLLECTION_NAME = "nist_800_53_r5"
_EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"

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

_ONNX_MODEL_DIR = _PROJECT_ROOT / "data" / "processed" / "onnx_model"


class OnnxEmbedder:
    """Lightweight embedding using ONNX Runtime instead of PyTorch.

    Produces identical embeddings to SentenceTransformer('bge-small-en-v1.5')
    but uses ~60MB RAM instead of ~400MB because it doesn't load the PyTorch
    framework. The ONNX model is exported during docker build by
    scripts/export_onnx_model.py.
    """

    def __init__(self, model_dir: Path) -> None:
        import onnxruntime as ort
        from tokenizers import Tokenizer

        self._session = ort.InferenceSession(
            str(model_dir / "model.onnx"),
            providers=["CPUExecutionProvider"],
        )
        self._tokenizer = Tokenizer.from_file(str(model_dir / "tokenizer.json"))
        self._input_names = [inp.name for inp in self._session.get_inputs()]

    def encode(self, text: str, normalize_embeddings: bool = True) -> np.ndarray:
        """Encode a single text string, matching SentenceTransformer.encode interface."""
        encoding = self._tokenizer.encode(text)

        input_ids = np.array([encoding.ids], dtype=np.int64)
        attention_mask = np.array([encoding.attention_mask], dtype=np.int64)

        feeds: dict[str, np.ndarray] = {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
        }
        # bge-small is BERT-based and expects token_type_ids
        if "token_type_ids" in self._input_names:
            feeds["token_type_ids"] = np.zeros_like(input_ids)

        # output shape: [1, seq_len, 384]
        last_hidden_state = self._session.run(None, feeds)[0]

        # CLS pooling: bge-small uses the first token's embedding
        embedding = last_hidden_state[0, 0, :]

        if normalize_embeddings:
            norm = np.linalg.norm(embedding)
            if norm > 0:
                embedding = embedding / norm

        return embedding


_model: OnnxEmbedder | None = None
_collection: chromadb.Collection | None = None


def _get_embedding_model() -> OnnxEmbedder:
    """Load the ONNX embedding model once and cache it.

    Falls back to SentenceTransformer for local development if the ONNX
    model hasn't been exported yet (run scripts/export_onnx_model.py).
    """
    global _model
    if _model is None:
        onnx_path = _ONNX_MODEL_DIR / "model.onnx"
        if onnx_path.exists():
            logger.info("Loading ONNX embedding model from %s", _ONNX_MODEL_DIR)
            _model = OnnxEmbedder(_ONNX_MODEL_DIR)
        else:
            # local dev fallback: sentence-transformers with full PyTorch
            logger.info(
                "ONNX model not found at %s, falling back to SentenceTransformer",
                onnx_path,
            )
            from sentence_transformers import SentenceTransformer
            _model = SentenceTransformer(_EMBEDDING_MODEL)  # type: ignore[assignment]
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
    vocabulary (no vendor names, no CVE jargon) so the embedding model
    lands directly on the correct base controls.

    The primary query (build_query) captures full context; this one
    targets precision.
    """
    desc_lower = risk.description.lower()
    for patterns, focused in _VULN_TYPE_FOCUSED_QUERIES:
        if any(p in desc_lower for p in patterns):
            logger.debug("Built focused query: %s", focused)
            return focused
    return None



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



def _parse_document(doc: str) -> dict[str, str | list[str]]:
    """Parse a Chroma document back into structured fields.

    The document was stored in the format produced by
    scripts/build_nist_index.py:format_chunk (a newline-separated block
    with labeled fields).
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



def _query_chroma(
    collection: chromadb.Collection,
    model: OnnxEmbedder,
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

    Two queries bridge the vocabulary gap between CVE descriptions and
    NIST prose: a primary query (full context, vendor jargon) and a
    focused query (NIST vocabulary only). Results are combined via
    round-robin interleave so both queries contribute to the final
    top-k. Family boost (+0.03) is applied before interleaving.
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

    # over-fetch to give family boost room to promote relevant controls
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

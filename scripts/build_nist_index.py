"""Build the NIST 800-53 Rev 5 Chroma vector index.

Idempotent. Use --force to rebuild from scratch.
"""

import argparse
import json
import logging
import shutil
import urllib.request
from pathlib import Path

import chromadb
from sentence_transformers import SentenceTransformer

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

# NIST OSCAL catalog: authoritative source for SP 800-53 Rev 5 controls
OSCAL_URL = (
    "https://raw.githubusercontent.com/usnistgov/oscal-content"
    "/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json"
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
OSCAL_CACHE_PATH = PROJECT_ROOT / "data" / "reference" / "nist_800_53_r5.json"
CHROMA_PATH = PROJECT_ROOT / "data" / "processed" / "nist_chroma"

COLLECTION_NAME = "nist_800_53_r5"
EMBEDDING_MODEL = "BAAI/bge-small-en-v1.5"



def download_oscal(force: bool = False) -> dict:
    """Download the OSCAL catalog JSON and cache locally.

    Skips download if cache exists and force is False.
    """
    if OSCAL_CACHE_PATH.exists() and not force:
        cached = json.loads(OSCAL_CACHE_PATH.read_text(encoding="utf-8"))
        # placeholder file has an empty controls list, treat as missing
        if "catalog" in cached:
            logger.info("Using cached OSCAL catalog at %s", OSCAL_CACHE_PATH)
            return cached
        logger.info("Cached file is a placeholder, downloading fresh copy")

    logger.info("Downloading OSCAL catalog from %s", OSCAL_URL)
    req = urllib.request.Request(
        OSCAL_URL, headers={"User-Agent": "TawasolPay-RiskAssistant/1.0"}
    )
    with urllib.request.urlopen(req, timeout=60) as response:
        raw = response.read().decode("utf-8")

    data = json.loads(raw)
    OSCAL_CACHE_PATH.parent.mkdir(parents=True, exist_ok=True)
    OSCAL_CACHE_PATH.write_text(raw, encoding="utf-8")
    logger.info("Cached OSCAL catalog to %s", OSCAL_CACHE_PATH)
    return data



def _collect_prose(part: dict) -> str:
    """Recursively collect prose from a part and its sub-parts.

    Statement parts nest items (a, b, c...) each with their own prose.
    We concatenate them with spaces to produce a readable block.
    """
    fragments: list[str] = []
    if "prose" in part:
        fragments.append(part["prose"])
    for sub in part.get("parts", []):
        fragments.append(_collect_prose(sub))
    return " ".join(fragments)


def _extract_related(links: list[dict]) -> list[str]:
    """Pull related control IDs from OSCAL link entries."""
    related: list[str] = []
    for link in links:
        if link.get("rel") == "related":
            # href is like "#ac-3", strip the leading hash and uppercase
            ctrl_id = link["href"].lstrip("#").upper()
            related.append(ctrl_id)
    return related


def _parse_control(control: dict, family_id: str, family_title: str) -> dict:
    """Parse a single OSCAL control into a flat dict for embedding.

    Returns dict with keys: control_id, title, family_id, family_title,
    statement, discussion, related_controls.
    """
    control_id = control.get("id", "").upper()
    title = control.get("title", "")

    statement = ""
    discussion = ""
    for part in control.get("parts", []):
        if part.get("name") == "statement":
            statement = _collect_prose(part)
        elif part.get("name") == "guidance":
            discussion = _collect_prose(part)

    related = _extract_related(control.get("links", []))

    return {
        "control_id": control_id,
        "title": title,
        "family_id": family_id,
        "family_title": family_title,
        "statement": statement,
        "discussion": discussion,
        "related_controls": related,
    }


def parse_catalog(catalog_data: dict) -> list[dict]:
    """Parse all controls (including enhancements) from the OSCAL catalog.

    Enhancements (e.g., AC-2(1)) are nested inside their parent control's
    "controls" array. We flatten them into the same list so each gets its
    own embedding and Chroma document.
    """
    controls: list[dict] = []
    groups = catalog_data.get("catalog", {}).get("groups", [])

    for group in groups:
        family_id = group.get("id", "").upper()
        family_title = group.get("title", "")

        for control in group.get("controls", []):
            controls.append(_parse_control(control, family_id, family_title))

            # control enhancements are nested controls
            for enhancement in control.get("controls", []):
                controls.append(
                    _parse_control(enhancement, family_id, family_title)
                )

    logger.info("Parsed %d controls (including enhancements)", len(controls))
    return controls



def format_chunk(control: dict) -> str:
    """Format a parsed control into a text chunk for embedding.

    Produces a structured block that gives the embedding model clear
    semantic anchors: control ID, name, family context, full statement,
    discussion rationale, and cross-references.
    """
    related_str = ", ".join(control["related_controls"]) if control["related_controls"] else "None"
    return (
        f"Control: {control['control_id']}\n"
        f"Name: {control['title']}\n"
        f"Family: {control['family_title']}\n"
        f"Statement: {control['statement']}\n"
        f"Discussion: {control['discussion']}\n"
        f"Related: {related_str}"
    )



def build_index(controls: list[dict]) -> None:
    """Embed control chunks and persist to Chroma.

    Uses BAAI/bge-small-en-v1.5 via sentence-transformers for embeddings.
    Chroma persists to disk at CHROMA_PATH so subsequent runs and the
    retrieval module can load without re-embedding.
    """
    chunks = [format_chunk(c) for c in controls]
    ids = [c["control_id"] for c in controls]
    metadatas = [
        {
            "control_id": c["control_id"],
            "family": c["family_title"],
            "title": c["title"],
        }
        for c in controls
    ]

    logger.info("Loading embedding model %s", EMBEDDING_MODEL)
    model = SentenceTransformer(EMBEDDING_MODEL)

    logger.info("Embedding %d chunks", len(chunks))
    embeddings = model.encode(chunks, show_progress_bar=True, normalize_embeddings=True)

    CHROMA_PATH.mkdir(parents=True, exist_ok=True)
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))

    # delete existing collection if present (we're in --force or first build)
    existing = [c.name for c in client.list_collections()]
    if COLLECTION_NAME in existing:
        client.delete_collection(COLLECTION_NAME)
        logger.info("Deleted existing collection '%s'", COLLECTION_NAME)

    collection = client.create_collection(
        name=COLLECTION_NAME,
        metadata={"description": "NIST SP 800-53 Rev 5 controls for RAG retrieval"},
    )

    # Chroma has a batch size limit, insert in chunks of 500
    batch_size = 500
    for i in range(0, len(ids), batch_size):
        end = min(i + batch_size, len(ids))
        collection.add(
            ids=ids[i:end],
            embeddings=embeddings[i:end].tolist(),
            documents=chunks[i:end],
            metadatas=metadatas[i:end],
        )
    logger.info(
        "Persisted %d controls to Chroma at %s", collection.count(), CHROMA_PATH
    )



def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build NIST 800-53 Rev 5 Chroma vector index."
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Rebuild index even if the Chroma collection already exists.",
    )
    args = parser.parse_args()

    # skip if collection already populated
    if CHROMA_PATH.exists() and not args.force:
        try:
            client = chromadb.PersistentClient(path=str(CHROMA_PATH))
            existing = [c.name for c in client.list_collections()]
            if COLLECTION_NAME in existing:
                count = client.get_collection(COLLECTION_NAME).count()
                if count > 0:
                    logger.info(
                        "Collection '%s' already exists with %d controls. "
                        "Use --force to rebuild.",
                        COLLECTION_NAME,
                        count,
                    )
                    return
        except Exception:
            # corrupted or incompatible DB, fall through to rebuild
            logger.warning("Could not read existing Chroma DB, will rebuild")

    if args.force and CHROMA_PATH.exists():
        shutil.rmtree(CHROMA_PATH)
        logger.info("Removed existing Chroma directory for rebuild")

    catalog_data = download_oscal(force=args.force)
    controls = parse_catalog(catalog_data)

    if not controls:
        raise ValueError(
            "No controls parsed from OSCAL catalog. Check the download or format"
        )

    build_index(controls)


if __name__ == "__main__":
    main()

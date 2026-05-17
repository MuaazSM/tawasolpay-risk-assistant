"""Build the NIST 800-53 Rev 5 Chroma vector index.

Downloads the OSCAL JSON from NIST CSRC, parses each control into a chunk
(ID, title, family, statement, discussion, related controls), embeds with
BAAI/bge-small-en-v1.5, and persists to data/processed/nist_chroma/.
Idempotent with --force flag to rebuild from scratch.
"""


def main() -> None:
    raise NotImplementedError


if __name__ == "__main__":
    main()

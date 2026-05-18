# --- Stage 1: build dependencies and data artifacts ---
FROM python:3.11-slim AS builder

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/
COPY api/ api/

RUN pip install --no-cache-dir .

COPY data/raw/ data/raw/
COPY data/reference/ data/reference/
COPY scripts/ scripts/

RUN python scripts/fetch_kev.py && \
    python scripts/parse_threat_report.py && \
    python scripts/build_nist_index.py && \
    python scripts/export_onnx_model.py

# Remove PyTorch before copying to runtime — saves ~2GB disk and ~400MB RAM.
# The ONNX model replaces it for embedding inference.
RUN pip uninstall -y torch sentence-transformers && \
    pip install --no-cache-dir onnxruntime>=1.17 tokenizers>=0.15


# --- Stage 2: lean runtime image ---
FROM python:3.11-slim

WORKDIR /app

COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn

COPY src/ src/
COPY api/ api/
COPY pyproject.toml .

COPY --from=builder /app/data/ data/

EXPOSE 10000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "10000"]

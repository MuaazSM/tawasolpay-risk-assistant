# --- Stage 1: build dependencies and data artifacts ---
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build deps for numpy/pandas wheels if needed
RUN apt-get update && apt-get install -y --no-install-recommends gcc g++ && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY src/ src/
COPY api/ api/

RUN pip install --no-cache-dir .

# Copy data and scripts needed for the build steps
COPY data/raw/ data/raw/
COPY data/reference/ data/reference/
COPY scripts/ scripts/

# Build data artifacts: KEV cache, parsed campaigns, NIST Chroma index
RUN python scripts/fetch_kev.py && \
    python scripts/parse_threat_report.py && \
    python scripts/build_nist_index.py


# --- Stage 2: lean runtime image ---
FROM python:3.11-slim

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin/uvicorn /usr/local/bin/uvicorn

# Copy application code
COPY src/ src/
COPY api/ api/
COPY pyproject.toml .

# Copy all data (raw + reference + processed artifacts from build)
COPY --from=builder /app/data/ data/

EXPOSE 10000

CMD ["uvicorn", "api.main:app", "--host", "0.0.0.0", "--port", "10000"]

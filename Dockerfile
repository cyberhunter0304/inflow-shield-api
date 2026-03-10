# ============================================================================
# inFlow Shield API — Dockerfile
# Python 3.13 | FastAPI | Presidio | Torch | spaCy
# ============================================================================

FROM python:3.13-slim

# ── System deps ──────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# ── Working directory ────────────────────────────────────────────────────────
WORKDIR /app

# ── Install Python dependencies ──────────────────────────────────────────────
# Copy requirements first so Docker can cache this layer
COPY backend/requirements.txt .

RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# ── Download spaCy model ─────────────────────────────────────────────────────
# en_core_web_lg is required by Presidio for NLP-based PII detection
RUN python -m spacy download en_core_web_lg

# ── Copy application source ──────────────────────────────────────────────────
COPY backend/ .

# ── Environment defaults ─────────────────────────────────────────────────────
# Override these at runtime via --env-file or -e flags
ENV API_KEY=""
ENV INJECTION_THRESHOLD="0.8"
ENV TOXICITY_THRESHOLD="0.5"
ENV PII_THRESHOLD="0.5"
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

# ── Expose port ──────────────────────────────────────────────────────────────
EXPOSE 8001

# ── Health check ─────────────────────────────────────────────────────────────
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# ── Start server ─────────────────────────────────────────────────────────────
# --workers 1: ML models are not fork-safe; keep to single worker
# --timeout-keep-alive 30: hold connections open for warm subsequent requests
CMD ["uvicorn", "main:app", \
     "--host", "0.0.0.0", \
     "--port", "8001", \
     "--workers", "1", \
     "--timeout-keep-alive", "30"]
"""
inFlow Shield — Standalone Guardrails API
Scan-only. No LLM. No database. Pure security scanning as a service.

Usage:
    uvicorn main:app --reload --port 8001
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from routes.scan import router as scan_router
from scanner import preload_models, run_warmup
from security_scanner import shutdown_scanner

# Suppress noisy Presidio logs — same as main project
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logging.getLogger("presidio-analyzer").setLevel(logging.ERROR)

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # ── Startup ──────────────────────────────────────────────────────────────
    logger.info("=" * 60)
    logger.info("🚀  inFlow Shield API — starting up")
    logger.info("=" * 60)

    # Load all ML models synchronously (they are CPU-bound, not async)
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, preload_models)

    # Warmup — JIT-compile ONNX graphs so first real request is fast
    await run_warmup()

    logger.info("✅  All models ready — accepting requests")
    logger.info("✅  Scanners: PromptInjection | Toxicity | PII | Secrets")
    logger.info("=" * 60)

    yield  # ── Server running ─────────────────────────────────────────────

    # ── Shutdown ─────────────────────────────────────────────────────────────
    logger.info("🛑  inFlow Shield API — shutting down")
    shutdown_scanner()


app = FastAPI(
    title="inFlow Shield API",
    description=(
        "AI Guardrails as a Service — scan any message for "
        "PII, toxicity, prompt injection, and secrets."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000", "*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scan_router, prefix="/api/shield")


@app.get("/health")
async def health():
    return {"status": "ok", "service": "inflow-shield-api"}

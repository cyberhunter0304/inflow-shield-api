"""
inFlow Shield API — Scan Route
POST /api/shield/scan
"""
import logging
import os
from dotenv import load_dotenv

load_dotenv()

from fastapi import APIRouter, HTTPException, Security, status
from fastapi.security.api_key import APIKeyHeader
from models import ScanRequest, ScanResponse, Violation, LLMHandoff
from scanner import run_scan

logger = logging.getLogger(__name__)
router = APIRouter()

# ============================================================================
# API Key Auth
# ============================================================================
API_KEY        = os.getenv("API_KEY", "")
API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)


def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    if not API_KEY:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="API_KEY not configured on server",
        )
    if api_key != API_KEY:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing X-API-Key header",
        )
    return api_key


# ============================================================================
# Scan endpoint
# ============================================================================
@router.post("/scan", response_model=ScanResponse)
async def scan(
    request: ScanRequest,
    _: str = Security(verify_api_key),
):
    """
    Scan a user message through all guardrail checks.

    Returns unified JSON regardless of violation type:
    - allowed: whether the message passed all checks
    - violations: list of detected issues (type, confidence, action)
    - anonymized_prompt: redacted version if PII was found
    - llm_handoff: ready-to-use metadata + prompt for your LLM to handle blocked messages
    - scan_duration_ms: how long the full scan took

    No LLM is called here. No database. Pure ML scanning only.
    """
    if not request.message or not request.message.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="message field cannot be empty",
        )

    try:
        result = await run_scan(request.message)
    except Exception as e:
        logger.error(f"[scan] Unexpected error: {e}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Scan failed: {str(e)}",
        )

    violations = [Violation(**v) for v in result.get("violations", [])]

    llm_handoff = None
    if result.get("llm_handoff"):
        llm_handoff = LLMHandoff(**result["llm_handoff"])

    return ScanResponse(
        allowed           = result["allowed"],
        token_count       = result["token_count"],
        scan_duration_ms  = result["scan_duration_ms"],
        original_prompt   = result["original_prompt"],
        anonymized_prompt = result.get("anonymized_prompt"),
        violations        = violations,
        llm_handoff       = llm_handoff,
    )

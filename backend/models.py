"""
inFlow Shield API — Pydantic Schemas

Two groups:
  1. SecurityScanResult  — internal model used by security_scanner.py (mirrors main project)
  2. ScanRequest/ScanResponse — external API contract returned to Postman/callers
"""
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any


# ============================================================================
# INTERNAL — mirrors main project's SecurityScanResult
# security_scanner.py imports this directly
# ============================================================================

class SecurityScanResult(BaseModel):
    is_safe: bool
    detections: Dict[str, Any] = {}
    risk_level: str = "SAFE"
    message: str = "Prompt passed all security checks"
    timestamp: str = ""
    scan_duration: float = 0.0
    metrics: Dict[str, Any] = {}
    anonymized_prompt: Optional[str] = None
    detected_threats: List[str] = []


# ============================================================================
# EXTERNAL — API contract (what Postman sees)
# ============================================================================

class ScanRequest(BaseModel):
    message: str
    session_id: Optional[str] = None


class Violation(BaseModel):
    type: str         # "pii" | "toxicity" | "injection" | "secrets" | "token_limit"
    confidence: float
    action: str       # "blocked" | "anonymized"


class LLMHandoff(BaseModel):
    """
    Ready-to-use data for the API consumer's LLM.
    Drop prompt_for_llm into your system prompt — your LLM handles the response
    in its own voice. You own the personality, we own the security.
    """
    violation_type: str
    confidence_label: str        # "very high" | "high" | "moderate"
    message_length_label: str    # "very short" | "short" | "medium" | "long"
    suggested_tone: str
    prompt_for_llm: str          # ready-to-use prompt string for caller's LLM


class ScanResponse(BaseModel):
    allowed: bool
    token_count: int
    scan_duration_ms: int
    original_prompt: str
    anonymized_prompt: Optional[str] = None   # only present if PII detected
    violations: List[Violation] = []
    llm_handoff: Optional[LLMHandoff] = None  # only present if blocked

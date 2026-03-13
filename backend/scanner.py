"""
inFlow Shield API — Scanner Bootstrap (GPU Edition)
====================================================
Changes from CPU version:
  ✅ GPU setup is automatic — inflow_shield_lib handles CUDA + FP16 + compile
  ✅ run_warmup() runs two passes (JIT compile + steady state measurement)
  ✅ GPU info logged at startup for visibility
  ✅ gpu_metrics surfaced in run_scan() response
  ✅ All token helpers and LLM handoff logic unchanged
"""
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

_scanner = None


def preload_models():
    """
    Called once inside the FastAPI lifespan startup hook.

    Load order:
      1. import pii_detector      → Presidio + Secrets init (CPU or GPU spaCy)
      2. import security_scanner  → triggers PromptInjection + Toxicity init,
                                    which calls _get_pipeline() in the lib →
                                    CUDA detect → FP16 → torch.compile applied
      3. Instantiate ConcurrentSecurityScanner

    No manual GPU setup needed — the library handles everything.
    """
    global _scanner

    logger.info("[scanner] Preloading ML models...")

    try:
        import pii_detector  # noqa: F401 — loads Presidio + Secrets (CPU/GPU)

        from security_scanner import ConcurrentSecurityScanner

        # GPU info log (library already moved models + compiled at import time)
        import torch
        if torch.cuda.is_available():
            logger.info(
                f"[scanner] GPU: {torch.cuda.get_device_name(0)} | "
                f"VRAM: {torch.cuda.memory_allocated() / 1e6:.0f} MB used"
            )

        _scanner = ConcurrentSecurityScanner()
        logger.info("[scanner] ✅ All models ready (PromptInjection, Toxicity, Presidio, Secrets)")

    except Exception as e:
        logger.error(f"[scanner] ❌ Model load failed: {e}")
        raise


async def run_warmup():
    """
    Two-pass warmup:
      Pass 1 — triggers torch.compile() JIT compilation (slow, expected)
      Pass 2 — measures true steady-state GPU latency
    """
    if _scanner is not None:
        await _scanner.warmup()


# ============================================================================
# Token helpers (unchanged)
# ============================================================================

MAX_TOKEN_CHARS = 2000  # ~500 tokens


def count_tokens(text: str) -> int:
    return max(1, len(text) // 4)


def get_length_label(char_count: int) -> str:
    if char_count < 50:  return "very short"
    if char_count < 150: return "short"
    if char_count < 400: return "medium"
    return "long"


def get_confidence_label(score: float) -> str:
    if score >= 0.9: return "very high"
    if score >= 0.7: return "high"
    return "moderate"


# ============================================================================
# LLM Handoff builder (unchanged)
# ============================================================================

_TONE_MAP = {
    "toxicity":         "calm and de-escalating",
    "injection":        "lightly humorous and firm",
    "prompt_injection": "lightly humorous and firm",
    "jailbreak":        "lightly humorous and firm",
    "pii":              "warm and protective",
    "secrets":          "serious and direct",
    "token_limit":      "helpful and informative",
}

_INSTRUCTION_MAP = {
    "toxicity":         "acknowledge the frustration might exist, redirect the user warmly without being preachy",
    "injection":        "let the user know their attempt didn't work without explaining why, keep it light",
    "prompt_injection": "let the user know their attempt didn't work without explaining why, keep it light",
    "jailbreak":        "let the user know their attempt didn't work without explaining why, keep it light",
    "pii":              "protect the user by asking them not to share personal information, make them feel safe not accused",
    "secrets":          "firmly tell the user to remove sensitive credentials before proceeding",
    "token_limit":      "politely ask the user to shorten their message and try again",
}


def build_llm_handoff(violation_type: str, confidence: float, char_count: int) -> dict:
    vtype            = violation_type.lower()
    confidence_label = get_confidence_label(confidence)
    length_label     = get_length_label(char_count)
    tone             = _TONE_MAP.get(vtype, "professional and firm")
    instruction      = _INSTRUCTION_MAP.get(vtype, "redirect the user politely")

    prompt = (
        f"A user message was blocked by the security system for: "
        f"{vtype} violation ({confidence_label} confidence, {length_label} message). "
        f"Generate a {tone} response that will {instruction}. "
        f"Do NOT reference the user's actual message. "
        f"Max 2 sentences. End with a soft redirect to what you can help with."
    )

    return {
        "violation_type":       vtype,
        "confidence_label":     confidence_label,
        "message_length_label": length_label,
        "suggested_tone":       tone,
        "prompt_for_llm":       prompt,
    }


# ============================================================================
# Main scan entry point (unchanged interface)
# ============================================================================

async def run_scan(message: str) -> Dict[str, Any]:
    """
    Called by routes/scan.py for every POST /api/shield/scan request.
    GPU acceleration is completely transparent to this function.
    """
    if _scanner is None:
        raise RuntimeError("Scanner not initialised — preload_models() was not called at startup")

    start_time  = time.monotonic()
    char_count  = len(message)
    token_count = count_tokens(message)

    # ── Token limit check ────────────────────────────────────────────────────
    if char_count > MAX_TOKEN_CHARS:
        elapsed = int((time.monotonic() - start_time) * 1000)
        return {
            "allowed":           False,
            "token_count":       token_count,
            "scan_duration_ms":  elapsed,
            "original_prompt":   message,
            "anonymized_prompt": None,
            "violations": [{
                "type":       "token_limit",
                "confidence": 1.0,
                "action":     "blocked",
            }],
            "llm_handoff": build_llm_handoff("token_limit", 1.0, char_count),
        }

    # ── Full GPU scan ────────────────────────────────────────────────────────
    scan_result = await _scanner.scan_prompt(message)

    elapsed    = int((time.monotonic() - start_time) * 1000)
    pii_data   = scan_result.detections.get("pii", {})
    has_pii    = pii_data.get("detected", False)
    pii_failed = pii_data.get("pii_scanner_failed", False)
    violations: list = []
    primary_violation: Optional[tuple] = None

    if pii_data.get("secrets_detected", False):
        score = float(pii_data.get("secrets_risk_score", 1.0))
        violations.append({"type": "secrets", "confidence": score, "action": "blocked"})
        primary_violation = primary_violation or ("secrets", score)

    if has_pii:
        violations.append({"type": "pii", "confidence": 0.95, "action": "anonymized"})

    injection_det = scan_result.detections.get("prompt_injection", {})
    if injection_det.get("detected", False):
        score = float(injection_det.get("risk_score", 0.9))
        violations.append({"type": "injection", "confidence": score, "action": "blocked"})
        primary_violation = primary_violation or ("injection", score)

    toxicity_det = scan_result.detections.get("toxicity", {})
    if toxicity_det.get("detected", False):
        score = float(toxicity_det.get("risk_score", 0.8))
        violations.append({"type": "toxicity", "confidence": score, "action": "blocked"})
        primary_violation = primary_violation or ("toxicity", score)

    llm_handoff = None
    if not scan_result.is_safe and primary_violation:
        vtype, vconf = primary_violation
        llm_handoff = build_llm_handoff(vtype, vconf, char_count)

    return {
        "allowed":             scan_result.is_safe,
        "token_count":         token_count,
        "scan_duration_ms":    elapsed,
        "original_prompt":     message,
        "anonymized_prompt":   pii_data.get("anonymized_prompt") if has_pii else None,
        "violations":          violations,
        "llm_handoff":         llm_handoff,
        "pii_scanner_error":   pii_data.get("error") if pii_failed else None,
        "gpu_metrics":         scan_result.metrics,  # per-scanner ms + device info
    }
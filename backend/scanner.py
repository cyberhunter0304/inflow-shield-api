"""
inFlow Shield API — Scanner Bootstrap (GPU Edition)
====================================================
Built from actual ConcurrentSecurityScanner introspection:

  Methods available:
    scan_prompt()          — sequential scan  (~400ms)
    scan_prompt_parallel() — parallel scan    (target: ~120ms)
    warmup()               — two-pass JIT warmup
    _run_toxicity_gpu()    — internal
    _run_injection_gpu()   — internal
    _run_pii_scanner()     — internal

  Result shape (SecurityScanResult):
    .is_safe               bool
    .detections            dict  — keys: toxicity, prompt_injection, pii
    .risk_level            str   — 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    .scan_duration         float — total wall time in SECONDS
    .metrics               dict  — {
                                     total_scan_time: float (seconds),
                                     scanner_times: {
                                       toxicity: float (seconds),
                                       prompt_injection: float (seconds),
                                       pii: float (seconds),
                                     },
                                     execution_mode: str,
                                     cache_hit: bool,
                                     gpu_device: str,
                                   }
    .anonymized_prompt     str | None
    .detected_threats      list[str]

  All times in metrics are SECONDS — multiplied by 1000 for ms display.
"""
import time
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

_scanner = None


def preload_models():
    """
    Called once at startup. Imports trigger CUDA + FP16 + torch.compile inside
    the library — no manual GPU setup needed.
    """
    global _scanner

    logger.info("[scanner] Preloading ML models...")

    try:
        import pii_detector  # noqa: F401 — loads Presidio + Secrets

        from security_scanner import ConcurrentSecurityScanner

        import torch
        if torch.cuda.is_available():
            logger.info(
                f"[scanner] GPU: {torch.cuda.get_device_name(0)} | "
                f"VRAM allocated: {torch.cuda.memory_allocated() / 1e6:.0f} MB"
            )

        _scanner = ConcurrentSecurityScanner()
        logger.info("[scanner] ✅ All models ready")

    except Exception as e:
        logger.error(f"[scanner] ❌ Model load failed: {e}")
        raise


async def run_warmup():
    """
    Two-pass warmup using scan_prompt_parallel — warms both the JIT compile
    path and the parallel code path in the library.
    """
    if _scanner is None:
        return

    warmup_msg = "Hello, how can you help me today?"
    logger.info("[scanner] Warmup pass 1 (JIT compile)...")
    try:
        await _scanner.scan_prompt_parallel(warmup_msg)
    except Exception:
        await _scanner.scan_prompt(warmup_msg)

    logger.info("[scanner] Warmup pass 2 (steady state)...")
    try:
        await _scanner.scan_prompt_parallel(warmup_msg)
    except Exception:
        await _scanner.scan_prompt(warmup_msg)

    logger.info("[scanner] ✅ Warmup complete")


# ============================================================================
# Token helpers
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
# LLM Handoff builder
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
# Result parser — converts SecurityScanResult → clean API dict
# ============================================================================

def _parse_result(scan_result, start_time: float, message: str) -> Dict[str, Any]:
    """
    Converts a SecurityScanResult object into the standardised API response dict.

    IMPORTANT: scan_result.metrics["scanner_times"] values are in SECONDS.
    We convert to ms here once, correctly.
    """
    char_count = len(message)
    wall_ms    = round((time.monotonic() - start_time) * 1000, 2)

    pii_data       = scan_result.detections.get("pii", {})
    injection_data = scan_result.detections.get("prompt_injection", {})
    toxicity_data  = scan_result.detections.get("toxicity", {})

    has_pii    = pii_data.get("detected", False)
    pii_failed = pii_data.get("pii_scanner_failed", False)

    violations: list = []
    primary_violation: Optional[tuple] = None

    # Secrets (reported inside pii detection)
    if pii_data.get("secrets_detected", False):
        score = float(pii_data.get("secrets_risk_score", 1.0))
        violations.append({"type": "secrets", "confidence": score, "action": "blocked"})
        primary_violation = primary_violation or ("secrets", score)

    # PII — allowed but anonymized
    if has_pii:
        violations.append({"type": "pii", "confidence": 0.95, "action": "anonymized"})

    # Prompt injection
    if injection_data.get("detected", False):
        score = float(injection_data.get("risk_score", 0.9))
        violations.append({"type": "injection", "confidence": score, "action": "blocked"})
        primary_violation = primary_violation or ("injection", score)

    # Toxicity
    if toxicity_data.get("detected", False):
        score = float(toxicity_data.get("risk_score", 0.8))
        violations.append({"type": "toxicity", "confidence": score, "action": "blocked"})
        primary_violation = primary_violation or ("toxicity", score)

    llm_handoff = None
    if not scan_result.is_safe and primary_violation:
        vtype, vconf = primary_violation
        llm_handoff = build_llm_handoff(vtype, vconf, char_count)

    # scanner_times from library are in SECONDS → convert to ms
    raw_times   = scan_result.metrics.get("scanner_times", {})
    per_scan_ms = {k: round(v * 1000, 2) for k, v in raw_times.items()}

    return {
        "allowed":           scan_result.is_safe,
        "token_count":       count_tokens(message),
        "scan_duration_ms":  round(scan_result.scan_duration * 1000, 2),
        "wall_time_ms":      wall_ms,
        "original_prompt":   message,
        "anonymized_prompt": pii_data.get("anonymized_prompt") if has_pii else None,
        "violations":        violations,
        "detected_threats":  scan_result.detected_threats,
        "risk_level":        scan_result.risk_level,
        "llm_handoff":       llm_handoff,
        "pii_scanner_error": pii_data.get("error") if pii_failed else None,
        "gpu_metrics": {
            "per_scanner_ms":  per_scan_ms,        # toxicity / prompt_injection / pii
            "scan_duration_ms": round(scan_result.scan_duration * 1000, 2),
            "wall_time_ms":    wall_ms,
            "execution_mode":  scan_result.metrics.get("execution_mode", "unknown"),
            "cache_hit":       scan_result.metrics.get("cache_hit", False),
            "gpu_device":      scan_result.metrics.get("gpu_device", "unknown"),
        },
    }


# ============================================================================
# Main scan entry point
# ============================================================================

async def run_scan(message: str) -> Dict[str, Any]:
    """
    Uses scan_prompt_parallel() — the library's own parallel implementation.
    Falls back to scan_prompt() (sequential) if parallel raises.
    """
    if _scanner is None:
        raise RuntimeError("Scanner not initialised — call preload_models() at startup")

    start_time = time.monotonic()
    char_count = len(message)

    # ── Token limit fast path ─────────────────────────────────────────────────
    if char_count > MAX_TOKEN_CHARS:
        wall_ms = round((time.monotonic() - start_time) * 1000, 2)
        return {
            "allowed":           False,
            "token_count":       count_tokens(message),
            "scan_duration_ms":  wall_ms,
            "wall_time_ms":      wall_ms,
            "original_prompt":   message,
            "anonymized_prompt": None,
            "violations":        [{"type": "token_limit", "confidence": 1.0, "action": "blocked"}],
            "detected_threats":  ["token_limit"],
            "risk_level":        "CRITICAL",
            "llm_handoff":       build_llm_handoff("token_limit", 1.0, char_count),
            "pii_scanner_error": None,
            "gpu_metrics":       {},
        }

    # ── Parallel GPU scan ─────────────────────────────────────────────────────
    try:
        scan_result = await _scanner.scan_prompt_parallel(message)
    except Exception as e:
        logger.warning(f"[scanner] parallel failed ({e}), falling back to sequential")
        scan_result = await _scanner.scan_prompt(message)

    return _parse_result(scan_result, start_time, message)
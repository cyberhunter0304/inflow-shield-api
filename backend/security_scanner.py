"""
Security Scanner Module — SECURITY-FIRST DESIGN
Identical to main project. Only change: llm_guard → inflow_shield_lib

- ALL scanners run ALWAYS (no early exit)
- Complete detection logging for audit trails
- Result caching for identical prompts (safe speedup)
- Sequential execution (CPU-bound, GIL-friendly)
"""
import logging
import time
import hashlib
import re
from typing import Dict, Any
from inflow_shield_lib import PromptInjection, Toxicity
from pii_detector import ThreadSafePIIDetector
from models import SecurityScanResult
from config import SCANNER_CONFIG
from datetime_utils import now

logger = logging.getLogger(__name__)

# ============================================================================
# RESULT CACHE
# ============================================================================
_SCAN_CACHE: Dict[str, SecurityScanResult] = {}
_CACHE_MAX_SIZE = 1000


def _get_prompt_hash(prompt: str) -> str:
    return hashlib.sha256(prompt.encode()).hexdigest()[:16]


# ============================================================================
# SCANNER INITIALIZATION — module level, loaded once at startup
# ============================================================================
prompt_injection_scanner = PromptInjection(
    threshold=SCANNER_CONFIG["prompt_injection_threshold"]
)
toxicity_scanner = Toxicity(
    threshold=SCANNER_CONFIG["toxicity_threshold"]
)

MAX_SCAN_LENGTH = 512


class ConcurrentSecurityScanner:
    """
    High-Performance Security Scanner — identical to main project.
    ✅ All scanners run on every request
    ✅ Result caching for identical prompts
    ✅ Warmup at startup to eliminate cold-start penalty
    ✅ Fully async — works with FastAPI's event loop
    """

    def __init__(self):
        self.scanners = {
            "prompt_injection": prompt_injection_scanner,
            "toxicity":         toxicity_scanner,
        }

    def _preprocess_prompt(self, prompt: str) -> str:
        if len(prompt) > MAX_SCAN_LENGTH:
            truncated = prompt[:MAX_SCAN_LENGTH]
            logger.debug(f"[OPTIMIZE] Truncated: {len(prompt)} → {len(truncated)} chars")
            return truncated
        return prompt

    def _run_single_scanner(self, scanner_name: str, scanner, prompt: str) -> Dict[str, Any]:
        start_time = time.time()
        try:
            sanitized, is_valid, risk_score = scanner.scan(prompt)
            execution_time = time.time() - start_time
            result = {
                "is_valid":       is_valid,
                "risk_score":     float(risk_score),
                "detected":       not is_valid,
                "execution_time": execution_time,
            }
            logger.debug(f"[SCAN] {scanner_name}: {execution_time:.3f}s (score: {risk_score:.2f})")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"[SCAN] {scanner_name} error: {str(e)}")
            return {
                "error":          str(e),
                "is_valid":       True,
                "risk_score":     0.0,
                "execution_time": execution_time,
            }

    def _run_pii_scanner(self, prompt: str) -> Dict[str, Any]:
        start_time = time.time()
        try:
            anonymized_prompt, pii_entities, scanner_results = ThreadSafePIIDetector.anonymize(prompt)
            execution_time = time.time() - start_time
            secrets_result = scanner_results.get("secrets", {})
            result = {
                "is_valid":          len(pii_entities) == 0,
                "risk_score":        1.0 if pii_entities else 0.0,
                "detected":          len(pii_entities) > 0,
                "entities_found":    len(pii_entities),
                "entity_types":      list(set([e["type"] for e in pii_entities])) if pii_entities else [],
                "entities":          pii_entities,
                "anonymized_prompt": anonymized_prompt,
                "anonymized":        len(pii_entities) > 0,
                "execution_time":    execution_time,
                "entity_count":      len(pii_entities),
                "secrets_detected":  secrets_result.get("detected", False),
                "secrets_risk_score": secrets_result.get("risk_score", 0.0),
            }
            logger.debug(f"[SCAN] PII: {execution_time:.3f}s ({len(pii_entities)} entities)")
            return result
        except Exception as e:
            execution_time = time.time() - start_time
            logger.error(f"[SCAN] PII error: {str(e)}")
            return {
                "error":             str(e),
                "is_valid":          True,
                "risk_score":        0.0,
                "detected":          False,
                "anonymized_prompt": prompt,
                "execution_time":    execution_time,
                "secrets_detected":  False,
                "secrets_risk_score": 0.0,
            }

    async def warmup(self):
        logger.info("=" * 60)
        logger.info("🔥 Warming up security scanners (JIT + CPU cache)...")
        logger.info("=" * 60)
        warmup_start = time.time()
        try:
            await self.scan_prompt(
                "Hello, this is a warmup request to pre-compile models.",
                bot_id="__warmup__"
            )
            warmup_time = time.time() - warmup_start
            logger.info(f"✅ Warmup complete in {warmup_time:.2f}s")
            logger.info("   First real request will be fast!")
        except Exception as e:
            logger.warning(f"⚠️  Warmup failed (non-fatal): {e}")
        logger.info("=" * 60)

    async def scan_prompt_parallel(self, prompt: str, bot_id: str = "unknown") -> SecurityScanResult:
        """
        Main scan logic — identical to main project.
        All 3 scanners always run. No early exit.
        """
        scan_start_time = time.time()

        # Cache check
        prompt_hash = _get_prompt_hash(prompt)
        if prompt_hash in _SCAN_CACHE:
            cached = _SCAN_CACHE[prompt_hash]
            logger.info(f"[⚡ CACHE HIT] {prompt_hash[:8]}...")
            cached_dict = {
                "is_safe":         cached.is_safe,
                "detections":      cached.detections,
                "risk_level":      cached.risk_level,
                "message":         cached.message,
                "timestamp":       now(),
                "scan_duration":   cached.scan_duration,
                "metrics":         {**cached.metrics, "cache_hit": True},
            }
            return SecurityScanResult(**cached_dict)

        logger.debug(f"[Bot: {bot_id}] Running FULL security scan (all scanners)")

        processed_prompt = self._preprocess_prompt(prompt)

        results = {
            "is_safe":     True,
            "detections":  {},
            "risk_level":  "SAFE",
            "message":     "Prompt passed all security checks",
            "timestamp":   now(),
            "scan_duration": 0.0,
            "metrics": {
                "total_scan_time":  0.0,
                "scanner_times":    {},
                "scanner_count":    3,
                "execution_mode":   "sequential_full",
                "cache_hit":        False,
            },
        }

        timing_breakdown = {}

        # ── 1. Toxicity ──────────────────────────────────────────────────────
        toxicity_result = self._run_single_scanner("toxicity", toxicity_scanner, processed_prompt)
        timing_breakdown["TOXICITY"] = toxicity_result.get("execution_time", 0)
        results["detections"]["toxicity"] = toxicity_result

        # ── 2. Prompt Injection ──────────────────────────────────────────────
        injection_result = self._run_single_scanner("prompt_injection", prompt_injection_scanner, processed_prompt)
        timing_breakdown["PROMPT_INJECTION"] = injection_result.get("execution_time", 0)
        results["detections"]["prompt_injection"] = injection_result

        # ── 3. PII / Secrets ─────────────────────────────────────────────────
        pii_result = self._run_pii_scanner(processed_prompt)
        timing_breakdown["PII"] = pii_result.get("execution_time", 0)
        results["detections"]["pii"] = pii_result

        # ── Threat evaluation ────────────────────────────────────────────────
        detected_threats = []
        max_risk_score = 0.0

        pii_results = results["detections"].get("pii", {})

        # Secrets
        if pii_results.get("secrets_detected", False):
            results["is_safe"] = False
            detected_threats.append("Secrets")
            max_risk_score = max(max_risk_score, pii_results.get("secrets_risk_score", 0.0))

        # PII (logged but does NOT block on its own)
        if pii_results.get("detected", False):
            detected_threats.append("PII")

        # Toxicity
        toxicity_det = results["detections"].get("toxicity", {})
        if not toxicity_det.get("is_valid", True):
            results["is_safe"] = False
            detected_threats.append("Toxicity")
            max_risk_score = max(max_risk_score, toxicity_det.get("risk_score", 0.0))

        # Prompt Injection — with false-positive suppression
        injection_det = results["detections"].get("prompt_injection", {})
        injection_detected = not injection_det.get("is_valid", True)

        if injection_detected and pii_results.get("detected", False):
            pii_entity_count = pii_results.get("entity_count", 0)
            prompt_word_count = len(prompt.split())
            if pii_entity_count > 0 and prompt_word_count < 10:
                injection_risk = injection_det.get("risk_score", 0.0)
                logger.debug(
                    f"[INJECTION] Suppressing false positive — PII dominant prompt "
                    f"(risk was {injection_risk:.2f})"
                )
                injection_detected = False
                injection_det["suppressed_by_pii_filter"] = True

        # Expanded jailbreak keyword detection
        jailbreak_keywords = [
            r'\bDAN\b',
            r'\bdeveloper\s*mode\b',
            r'\bjailbreak\b',
            r'\bact\s+as\s+(?:an?\s+)?(?:evil|unfiltered|unrestricted)',
            r'\bignore\s+(?:all\s+)?(?:previous|prior|above)\s+instructions?\b',
            r'\bforget\s+(?:all\s+)?(?:your\s+)?(?:rules|instructions|guidelines)\b',
            r'\bpretend\s+(?:you\s+are|to\s+be)\s+(?:an?\s+)?(?:different|other|new)\b',
            r'\bdisregard\s+(?:all\s+)?(?:safety|content)\s+(?:rules|policies|guidelines)\b',
        ]
        prompt_lower = prompt.lower()
        for pattern in jailbreak_keywords:
            if re.search(pattern, prompt_lower, re.IGNORECASE):
                injection_detected = True
                injection_det["keyword_match"] = pattern
                logger.info(f"[INJECTION] Keyword pattern matched: {pattern}")
                break

        if injection_detected:
            results["is_safe"] = False
            detected_threats.append("Prompt Injection")
            max_risk_score = max(max_risk_score, injection_det.get("risk_score", 0.0))

        # ── Finalise ─────────────────────────────────────────────────────────
        scan_duration = time.time() - scan_start_time
        results["scan_duration"] = scan_duration
        results["metrics"]["total_scan_time"] = round(scan_duration, 4)

        for scanner_name, exec_time in timing_breakdown.items():
            results["metrics"]["scanner_times"][scanner_name.lower()] = round(exec_time, 4)

        if not results["is_safe"]:
            if max_risk_score >= 0.8:
                results["risk_level"] = "CRITICAL"
            elif max_risk_score >= 0.6:
                results["risk_level"] = "HIGH"
            else:
                results["risk_level"] = "MEDIUM"

            blocking_threats = [t for t in detected_threats if t != "PII"]
            friendly_messages = {
                "Prompt Injection": "I'm sorry, but I cannot process this request. Please rephrase your question.",
                "Toxicity":         "Please ask your question respectfully. I'm here to help when you communicate kindly.",
                "Secrets":          "Your message contains sensitive credentials. Please remove them before continuing.",
            }
            if len(blocking_threats) == 1:
                results["message"] = friendly_messages.get(
                    blocking_threats[0],
                    "I'm unable to process this request. Please try rephrasing."
                )
            elif len(blocking_threats) > 1:
                results["message"] = (
                    f"Multiple security issues detected ({', '.join(blocking_threats)}). "
                    "Please rephrase your request."
                )

        results["anonymized_prompt"] = pii_result.get("anonymized_prompt", prompt)
        results["detected_threats"]  = detected_threats

        # Cache
        result_obj = SecurityScanResult(**results)
        if len(_SCAN_CACHE) >= _CACHE_MAX_SIZE:
            oldest_keys = list(_SCAN_CACHE.keys())[:100]
            for k in oldest_keys:
                _SCAN_CACHE.pop(k, None)
        _SCAN_CACHE[prompt_hash] = result_obj

        timing_parts = [f"{name}:{t:.2f}s" for name, t in timing_breakdown.items()]
        threats_str  = f" | THREATS: {detected_threats}" if detected_threats else ""
        logger.info(f"[SCAN] {' | '.join(timing_parts)}{threats_str} (total: {scan_duration:.2f}s)")

        return result_obj

    async def scan_prompt(self, prompt: str, bot_id: str = "unknown") -> SecurityScanResult:
        return await self.scan_prompt_parallel(prompt, bot_id)


def shutdown_scanner():
    logger.info("SecurityScanner shutdown called")

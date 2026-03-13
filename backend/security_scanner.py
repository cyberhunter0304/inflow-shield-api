"""
Security Scanner Module — GPU-ACCELERATED (T4 Optimized)
=========================================================
What changed from CPU version:

LIBRARY SIDE (prompt_injection.py + toxicity.py):
  ✅ torch.compile() applied to pipeline.model inside _get_pipeline()
     — Toxicity: mode=reduce-overhead (CUDA graphs, fixed [1,512] shape)
     — Injection: mode=default (safe for variable-length inputs)
  ✅ FP16 (torch_dtype=float16) already handled by the library
  ✅ CUDA device placement already handled by the library

API SIDE (this file):
  ✅ Per-scanner CUDA streams — torch.cuda.stream() wraps each pipeline
     call so Toxicity + Injection overlap on the GPU simultaneously
  ✅ torch.cuda.synchronize() after asyncio.gather() to flush both streams
  ✅ GPU metrics surfaced in scan result (device, per-scanner ms)
  ✅ All original security logic preserved (no compromises)

What was REMOVED vs previous version:
  ✗ _move_model_to_gpu() — models are already on GPU (library handles it)
  ✗ _compile_model()     — compile now lives inside _get_pipeline() in lib
  ✗ setup_gpu_models()   — no longer needed (library self-configures)
"""
import logging
import time
import hashlib
import re
import asyncio
import concurrent.futures
from typing import Dict, Any, Optional

import torch

from inflow_shield_lib import PromptInjection, Toxicity
from pii_detector import ThreadSafePIIDetector
from models import SecurityScanResult
from config import SCANNER_CONFIG
from datetime_utils import now

logger = logging.getLogger(__name__)

# ============================================================================
# GPU INFO
# ============================================================================
USE_GPU = torch.cuda.is_available()

if USE_GPU:
    _GPU_NAME = torch.cuda.get_device_name(0)
    _GPU_VRAM = torch.cuda.get_device_properties(0).total_memory / 1e9
    logger.info(f"[GPU] Device : {_GPU_NAME}")
    logger.info(f"[GPU] VRAM   : {_GPU_VRAM:.1f} GB")
    logger.info("[GPU] FP16   : yes (handled by inflow_shield_lib)")
    logger.info("[GPU] compile: yes (torch.compile in pipeline, see lib logs)")
    # One CUDA stream per scanner — lets Toxicity + Injection overlap on GPU
    _STREAM_TOX = torch.cuda.Stream()
    _STREAM_INJ = torch.cuda.Stream()
else:
    _GPU_NAME   = "cpu"
    _GPU_VRAM   = 0.0
    _STREAM_TOX = None
    _STREAM_INJ = None
    logger.warning("[GPU] CUDA not available — running on CPU")

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
# Instantiating these triggers _get_pipeline() inside the library, which:
#   1. Detects CUDA → uses device=0
#   2. Sets torch_dtype=float16 on GPU
#   3. Applies torch.compile() to pipeline.model
# All GPU setup happens automatically — no manual model moves needed.
prompt_injection_scanner = PromptInjection(
    threshold=SCANNER_CONFIG["prompt_injection_threshold"]
)
toxicity_scanner = Toxicity(
    threshold=SCANNER_CONFIG["toxicity_threshold"]
)

MAX_SCAN_LENGTH = 512


# ============================================================================
# CONCURRENT SECURITY SCANNER
# ============================================================================

class ConcurrentSecurityScanner:
    """
    GPU-Accelerated Security Scanner for inFlow Shield.

    ✅ All scanners run on every request (security-first — no early exit)
    ✅ Result caching for identical prompts
    ✅ Toxicity + Injection run on SEPARATE CUDA streams → true GPU overlap
    ✅ torch.cuda.synchronize() after gather → results stable before read
    ✅ PII on CPU (or GPU if spacy.prefer_gpu() enabled in pii_detector.py)
    ✅ GPU metrics in every scan response for observability
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

    def _run_toxicity_gpu(self, prompt: str) -> Dict[str, Any]:
        """
        Toxicity scan on its own CUDA stream.

        torch.cuda.stream(_STREAM_TOX) makes all CUDA ops inside this call
        execute on stream_tox. Because _run_injection_gpu uses stream_inj,
        both run simultaneously on the GPU instead of serialising.

        The library pipeline already handles FP16 + torch.compile internally.
        """
        start = time.time()
        try:
            if USE_GPU and _STREAM_TOX is not None:
                with torch.cuda.stream(_STREAM_TOX):
                    sanitized, is_valid, risk_score = toxicity_scanner.scan(prompt)
            else:
                sanitized, is_valid, risk_score = toxicity_scanner.scan(prompt)

            exec_time = time.time() - start
            logger.debug(f"[SCAN] toxicity: {exec_time*1000:.1f}ms (score={risk_score:.2f})")
            return {
                "is_valid":       is_valid,
                "risk_score":     float(risk_score),
                "detected":       not is_valid,
                "execution_time": exec_time,
            }
        except Exception as e:
            exec_time = time.time() - start
            logger.error(f"[SCAN] toxicity error: {e}")
            return {"error": str(e), "is_valid": True, "risk_score": 0.0, "execution_time": exec_time}

    def _run_injection_gpu(self, prompt: str) -> Dict[str, Any]:
        """
        PromptInjection scan on its own CUDA stream.
        Runs simultaneously with _run_toxicity_gpu on the GPU.
        """
        start = time.time()
        try:
            if USE_GPU and _STREAM_INJ is not None:
                with torch.cuda.stream(_STREAM_INJ):
                    sanitized, is_valid, risk_score = prompt_injection_scanner.scan(prompt)
            else:
                sanitized, is_valid, risk_score = prompt_injection_scanner.scan(prompt)

            exec_time = time.time() - start
            logger.debug(f"[SCAN] prompt_injection: {exec_time*1000:.1f}ms (score={risk_score:.2f})")
            return {
                "is_valid":       is_valid,
                "risk_score":     float(risk_score),
                "detected":       not is_valid,
                "execution_time": exec_time,
            }
        except Exception as e:
            exec_time = time.time() - start
            logger.error(f"[SCAN] prompt_injection error: {e}")
            return {"error": str(e), "is_valid": True, "risk_score": 0.0, "execution_time": exec_time}

    def _run_pii_scanner(self, prompt: str) -> Dict[str, Any]:
        """
        PII + Secrets — CPU (Presidio) or GPU if spacy.prefer_gpu() active.
        After GPU optimization of the other two, PII is the latency floor.
        """
        start = time.time()
        try:
            anonymized_prompt, pii_entities, scanner_results = ThreadSafePIIDetector.anonymize(prompt)
            exec_time      = time.time() - start
            secrets_result = scanner_results.get("secrets", {})
            result = {
                "is_valid":           len(pii_entities) == 0,
                "risk_score":         1.0 if pii_entities else 0.0,
                "detected":           len(pii_entities) > 0,
                "entities_found":     len(pii_entities),
                "entity_types":       list(set([e["type"] for e in pii_entities])) if pii_entities else [],
                "entities":           pii_entities,
                "anonymized_prompt":  anonymized_prompt,
                "anonymized":         len(pii_entities) > 0,
                "execution_time":     exec_time,
                "entity_count":       len(pii_entities),
                "secrets_detected":   secrets_result.get("detected", False),
                "secrets_risk_score": secrets_result.get("risk_score", 0.0),
            }
            logger.debug(f"[SCAN] PII: {exec_time*1000:.1f}ms ({len(pii_entities)} entities)")
            return result
        except Exception as e:
            exec_time = time.time() - start
            logger.error(f"[SCAN] PII FAILED: {e}", exc_info=True)
            return {
                "error":              str(e),
                "pii_scanner_failed": True,
                "is_valid":           True,
                "risk_score":         0.0,
                "detected":           False,
                "anonymized_prompt":  prompt,
                "execution_time":     exec_time,
                "secrets_detected":   False,
                "secrets_risk_score": 0.0,
            }

    async def warmup(self):
        """
        Two-pass warmup:
          Pass 1 — triggers torch.compile() JIT (~10–30s, expected)
          Pass 2 — measures true steady-state GPU latency
        """
        logger.info("=" * 60)
        logger.info("🔥 GPU Warmup — triggering torch.compile JIT...")
        logger.info("=" * 60)

        prompts = [
            "Hello, this is a warmup request to pre-compile CUDA kernels.",
            "Second warmup pass — measuring steady-state GPU latency.",
        ]
        for i, prompt in enumerate(prompts):
            t = time.time()
            try:
                await self.scan_prompt(prompt, bot_id="__warmup__")
                elapsed = (time.time() - t) * 1000
                label   = "JIT compile" if i == 0 else "steady state"
                logger.info(f"   Pass {i+1} ({label}): {elapsed:.0f} ms")
            except Exception as e:
                logger.warning(f"⚠️  Warmup pass {i+1} failed (non-fatal): {e}")

        if USE_GPU:
            logger.info(f"   VRAM used: {torch.cuda.memory_allocated() / 1e6:.0f} MB")

        logger.info("✅ Warmup complete — GPU kernels compiled, ready for requests")
        logger.info("=" * 60)

    async def scan_prompt_parallel(self, prompt: str, bot_id: str = "unknown") -> SecurityScanResult:
        """
        Main scan — all 3 scanners always run.

        Toxicity  → CUDA _STREAM_TOX ─┐
        Injection → CUDA _STREAM_INJ ─┼─ overlap on GPU simultaneously
        PII       → CPU thread        ─┘ runs concurrently

        torch.cuda.synchronize() after gather ensures both GPU streams
        have flushed before results are read.
        """
        scan_start = time.time()

        # ── Cache check ──────────────────────────────────────────────────────
        prompt_hash = _get_prompt_hash(prompt)
        if prompt_hash in _SCAN_CACHE:
            cached = _SCAN_CACHE[prompt_hash]
            logger.info(f"[⚡ CACHE HIT] {prompt_hash[:8]}...")
            return SecurityScanResult(**{
                "is_safe":           cached.is_safe,
                "detections":        cached.detections,
                "risk_level":        cached.risk_level,
                "message":           cached.message,
                "timestamp":         now(),
                "scan_duration":     cached.scan_duration,
                "metrics":           {**cached.metrics, "cache_hit": True},
                "anonymized_prompt": cached.anonymized_prompt,
                "detected_threats":  cached.detected_threats,
            })

        logger.debug(f"[Bot: {bot_id}] GPU scan — all scanners running")
        processed_prompt = self._preprocess_prompt(prompt)

        results = {
            "is_safe":       True,
            "detections":    {},
            "risk_level":    "SAFE",
            "message":       "Prompt passed all security checks",
            "timestamp":     now(),
            "scan_duration": 0.0,
            "metrics": {
                "total_scan_time": 0.0,
                "scanner_times":   {},
                "scanner_count":   3,
                "execution_mode":  "gpu_streams_fp16_compiled" if USE_GPU else "cpu_parallel",
                "cache_hit":       False,
                "gpu_device":      _GPU_NAME,
            },
        }

        # ── Fire all 3 scanners simultaneously ───────────────────────────────
        loop = asyncio.get_event_loop()
        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
            tox_future = loop.run_in_executor(executor, self._run_toxicity_gpu, processed_prompt)
            inj_future = loop.run_in_executor(executor, self._run_injection_gpu, processed_prompt)
            pii_future = loop.run_in_executor(executor, self._run_pii_scanner, processed_prompt)

            toxicity_result, injection_result, pii_result = await asyncio.gather(
                tox_future, inj_future, pii_future
            )

        # Flush both CUDA streams before reading results
        if USE_GPU:
            torch.cuda.synchronize()

        timing_breakdown = {
            "TOXICITY":         toxicity_result.get("execution_time", 0),
            "PROMPT_INJECTION": injection_result.get("execution_time", 0),
            "PII":              pii_result.get("execution_time", 0),
        }

        results["detections"]["toxicity"]        = toxicity_result
        results["detections"]["prompt_injection"] = injection_result
        results["detections"]["pii"]              = pii_result

        # ── Threat evaluation ────────────────────────────────────────────────
        detected_threats = []
        max_risk_score   = 0.0
        pii_results      = results["detections"].get("pii", {})

        if pii_results.get("secrets_detected", False):
            results["is_safe"] = False
            detected_threats.append("Secrets")
            max_risk_score = max(max_risk_score, pii_results.get("secrets_risk_score", 0.0))

        if pii_results.get("detected", False):
            detected_threats.append("PII")

        toxicity_det = results["detections"].get("toxicity", {})
        if not toxicity_det.get("is_valid", True):
            results["is_safe"] = False
            detected_threats.append("Toxicity")
            max_risk_score = max(max_risk_score, toxicity_det.get("risk_score", 0.0))

        injection_det      = results["detections"].get("prompt_injection", {})
        injection_detected = not injection_det.get("is_valid", True)

        # False-positive suppression (preserved)
        if injection_detected and pii_results.get("detected", False):
            if pii_results.get("entity_count", 0) > 0 and len(prompt.split()) < 10:
                logger.debug(f"[INJECTION] Suppressing false positive — PII dominant")
                injection_detected = False
                injection_det["suppressed_by_pii_filter"] = True

        # Jailbreak keyword detection (preserved)
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
        for pattern in jailbreak_keywords:
            if re.search(pattern, prompt, re.IGNORECASE):
                injection_detected             = True
                injection_det["detected"]      = True
                injection_det["keyword_match"] = pattern
                if injection_det.get("risk_score", 0.0) <= 0:
                    injection_det["risk_score"] = 1.0
                logger.info(f"[INJECTION] Keyword matched: {pattern}")
                break

        if injection_detected:
            results["is_safe"] = False
            detected_threats.append("Prompt Injection")
            max_risk_score = max(max_risk_score, injection_det.get("risk_score", 0.0))

        # ── Finalise ─────────────────────────────────────────────────────────
        scan_duration                         = time.time() - scan_start
        results["scan_duration"]              = scan_duration
        results["metrics"]["total_scan_time"] = round(scan_duration, 4)

        for k, v in timing_breakdown.items():
            results["metrics"]["scanner_times"][k.lower()] = round(v, 4)

        if not results["is_safe"]:
            if max_risk_score >= 0.8:
                results["risk_level"] = "CRITICAL"
            elif max_risk_score >= 0.6:
                results["risk_level"] = "HIGH"
            else:
                results["risk_level"] = "MEDIUM"

            blocking_threats  = [t for t in detected_threats if t != "PII"]
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

        result_obj = SecurityScanResult(**results)
        if len(_SCAN_CACHE) >= _CACHE_MAX_SIZE:
            for k in list(_SCAN_CACHE.keys())[:100]:
                _SCAN_CACHE.pop(k, None)
        _SCAN_CACHE[prompt_hash] = result_obj

        timing_parts = [f"{n}:{v*1000:.1f}ms" for n, v in timing_breakdown.items()]
        threats_str  = f" | THREATS: {detected_threats}" if detected_threats else ""
        mode_str     = f"GPU/{_GPU_NAME}" if USE_GPU else "CPU"
        logger.info(f"[{mode_str}] {' | '.join(timing_parts)}{threats_str} | total: {scan_duration*1000:.1f}ms")

        return result_obj

    async def scan_prompt(self, prompt: str, bot_id: str = "unknown") -> SecurityScanResult:
        return await self.scan_prompt_parallel(prompt, bot_id)


def shutdown_scanner():
    if USE_GPU:
        torch.cuda.empty_cache()
        logger.info(f"[GPU] VRAM freed. Remaining: {torch.cuda.memory_allocated() / 1e6:.0f} MB")
    logger.info("SecurityScanner shutdown complete")
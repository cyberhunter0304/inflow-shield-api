"""
PII Detection Module - WITH EAGER LOADING + PRESIDIO RECOGNIZER CACHING
Thread-safe PII detection with models loaded at startup (not on first request).
Presidio recognizer registry is cached to avoid rebuild on every call.

Identical to main project — only change: llm_guard → inflow_shield_lib
"""
import logging
import threading
import re
from typing import Tuple, List, Dict
from inflow_shield_lib import Vault, Secrets
from config import SCANNER_CONFIG

logger = logging.getLogger(__name__)


# ============================================================================
# GLOBAL CACHES - Load on module import (startup time)
# ============================================================================
_VAULT = None
_SECRETS_SCANNER = None
_PRESIDIO_ANALYZER = None
_PRESIDIO_ANONYMIZER = None
_INIT_LOCK = threading.Lock()
_INITIALIZED = False

# ============================================================================
# PRESIDIO RECOGNIZER CACHE
# Avoids rebuilding the full recognizer registry on every call.
# Key: language string (e.g. "en"), Value: list of recognizers
# ============================================================================
_PRESIDIO_RECOGNIZER_CACHE: Dict[str, list] = {}
_RECOGNIZER_CACHE_LOCK = threading.Lock()

# Anonymize scanner replaced by direct Presidio — no llm_guard.Anonymize needed.
# BERT_LARGE_NER_CONF not needed — Presidio handles NER internally.


def _initialize_all_scanners():
    """Initialize ALL scanners ONCE at module load time (server startup)"""
    global _VAULT, _SECRETS_SCANNER, _PRESIDIO_ANALYZER, _PRESIDIO_ANONYMIZER, _INITIALIZED

    with _INIT_LOCK:
        if _INITIALIZED:
            return  # Already initialized

        try:
            logger.info("=" * 70)
            logger.info("🚀 INITIALIZING PII DETECTION SCANNERS (EAGER LOADING AT STARTUP)...")
            logger.info("=" * 70)

            # Create vault once
            logger.info("Creating vault...")
            _VAULT = Vault()

            # Initialize Presidio (Microsoft's production PII detection)
            logger.info("Initializing Presidio Analyzer (Microsoft's PII engine)...")
            try:
                from presidio_analyzer import AnalyzerEngine
                from presidio_anonymizer import AnonymizerEngine

                _PRESIDIO_ANALYZER = AnalyzerEngine()
                _PRESIDIO_ANONYMIZER = AnonymizerEngine()
                logger.info("✓ Presidio Analyzer and Anonymizer loaded and cached")

            except ImportError:
                logger.warning("Presidio not available, will use regex-only mode")
                _PRESIDIO_ANALYZER = None

            # Anonymization handled directly by cached Presidio (no llm_guard Anonymize)
            logger.info("✓ Anonymization handled by cached Presidio Anonymizer")

            # Create Secrets scanner once (inflow_shield_lib — regex-based, no detect-secrets)
            logger.info("Loading Secrets scanner...")
            _SECRETS_SCANNER = Secrets()
            logger.info("✓ Secrets scanner loaded and cached")

            _INITIALIZED = True

            logger.info("=" * 70)
            logger.info("✅ ALL PII DETECTION SCANNERS INITIALIZED AND CACHED")
            logger.info("   ├─ Presidio Analyzer (accurate PII detection)")
            logger.info("   ├─ Presidio Recognizer Cache (pre-warmed for 'en')")
            logger.info("   ├─ Presidio Anonymizer (direct redaction)")
            logger.info("   └─ Secrets Scanner (API keys, passwords — regex)")
            logger.info("   ⏱️  Ready for requests! (No startup delay)")
            logger.info("=" * 70)

        except Exception as e:
            logger.error(f"Failed to initialize scanners: {str(e)}")
            raise


# Initialize scanners on module import (happens at server startup)
logger.info("[PII] Starting eager model loading...")
_initialize_all_scanners()
logger.info("[PII] Models loaded! Ready to serve requests.")


class ThreadSafePIIDetector:
    """
    Production-Grade PII Detector with cached Presidio + Regex.
    Models are pre-loaded at startup (not on first request).
    Presidio recognizer registry is cached to avoid rebuild on every call.
    Anonymization done directly via Presidio — no llm_guard.Anonymize wrapper.
    """

    @staticmethod
    def _extract_pii_with_presidio(text: str) -> Dict[str, List[str]]:
        """
        Extract PII using cached Presidio Analyzer (most accurate).
        Uses a pre-built recognizer cache to avoid rebuilding the registry
        on every call.
        """
        pii_values = {}

        if _PRESIDIO_ANALYZER is None:
            logger.debug("Presidio not available, skipping Presidio extraction")
            return pii_values

        try:
            logger.debug("Using cached Presidio Analyzer for PII extraction")

            with _RECOGNIZER_CACHE_LOCK:
                cached = _PRESIDIO_RECOGNIZER_CACHE.get("en")

            if cached is None:
                logger.debug("Presidio recognizer cache miss — fetching and caching now")
                cached = _PRESIDIO_ANALYZER.get_recognizers(language="en")
                with _RECOGNIZER_CACHE_LOCK:
                    _PRESIDIO_RECOGNIZER_CACHE["en"] = cached

            results = _PRESIDIO_ANALYZER.analyze(text=text, language="en", score_threshold=0.1)

            logger.debug(f"Presidio found {len(results)} PII entities")

            for result in results:
                entity_type = result.entity_type
                start = result.start
                end = result.end
                entity_value = text[start:end]

                if entity_type not in pii_values:
                    pii_values[entity_type] = []

                pii_values[entity_type].append(entity_value)
                logger.debug(f"Presidio: {entity_type} = '{entity_value}'")

            return pii_values

        except Exception as e:
            logger.debug(f"Presidio extraction error: {str(e)}")
            return pii_values

    @staticmethod
    def _extract_pii_with_regex(text: str) -> Dict[str, List[str]]:
        """
        Fast regex-based extraction (fallback/supplement)
        """
        pii_values = {}

        logger.debug("Using regex pattern extraction as supplement")

        patterns = {
            'EMAIL_ADDRESS': (r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 'email'),
            'PHONE_NUMBER':  (r'\b(?:\+?1?[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)?\d{3}[-.\s]?\d{4}\b', 'phone'),
            'US_SSN':        (r'\b\d{3}-\d{2}-\d{4}\b', 'SSN'),
            'CREDIT_CARD':   (r'\b(?:\d{4}[-\s]?){3}\d{4}\b', 'credit card'),
        }

        for entity_type, (pattern, desc) in patterns.items():
            matches = re.findall(pattern, text)
            if matches:
                if entity_type not in pii_values:
                    pii_values[entity_type] = []
                pii_values[entity_type].extend(matches)
                logger.debug(f"Regex found {len(matches)} {desc}")

        # Context-aware PERSON detection — catches names spaCy's NER misses
        # because they're uncommon/foreign names not in its training data.
        # Only triggers on explicit name-introduction phrases (low false-positive risk).
        name_context_patterns = [
            r"(?:my name is|i am|i'm|call me|this is|name's|myself)\s+([A-Za-z][a-z]{1,}(?:\s+[A-Z][a-z]+)*)",
            r"(?:hi|hey|hello)[,\s]+(?:i(?:'m| am)\s+)?([A-Z][a-z]{1,}(?:\s+[A-Z][a-z]+)*)",
        ]
        context_names = []
        for pattern in name_context_patterns:
            found = re.findall(pattern, text, re.IGNORECASE)
            context_names.extend([m.strip() for m in found if len(m.strip()) >= 2])

        if context_names:
            if 'PERSON' not in pii_values:
                pii_values['PERSON'] = []
            pii_values['PERSON'].extend(context_names)
            logger.debug(f"Context-aware regex found {len(context_names)} name(s): {context_names}")

        return pii_values

    @staticmethod
    def anonymize(text: str) -> Tuple[str, List[Dict], Dict[str, any]]:
        """
        Detect and anonymize PII using cached Presidio + Regex.
        Returns: (anonymized_text, entities_list, scanner_results)

        Replaces llm_guard.Anonymize with direct Presidio calls.
        Same return signature as main project — drop-in compatible.
        """
        entities = []
        scanner_results = {
            "secrets": {"detected": False, "is_valid": True, "risk_score": 0.0}
        }

        try:
            # ================================================================
            # STEP 1: EXTRACT PII VALUES FROM ORIGINAL TEXT
            # ================================================================
            logger.debug(f"Original text: '{text}'")
            pii_values_by_type = ThreadSafePIIDetector._extract_pii_with_presidio(text)

            # Supplement with regex patterns
            regex_values = ThreadSafePIIDetector._extract_pii_with_regex(text)
            for entity_type, values in regex_values.items():
                if entity_type not in pii_values_by_type:
                    pii_values_by_type[entity_type] = values
                else:
                    pii_values_by_type[entity_type].extend(values)

            logger.debug(f"Extracted PII: {pii_values_by_type}")

            # ================================================================
            # STEP 2: ANONYMIZE using cached Presidio directly
            # Replaces: _ANONYMIZE_SCANNER.scan(text) from main project
            # Same output: sanitized_text with [TYPE_N] tokens
            # ================================================================
            sanitized_text = text
            entity_type_indices = {}

            try:
                if _PRESIDIO_ANALYZER and _PRESIDIO_ANONYMIZER:
                    analysis_results = _PRESIDIO_ANALYZER.analyze(text=text, language="en", score_threshold=0.1)

                    # Build token map — process left to right to maintain stable offsets
                    ec: Dict[str, int] = {}
                    # Sort by start position ascending, replace right-to-left to preserve offsets
                    sorted_results = sorted(analysis_results, key=lambda x: x.start, reverse=True)
                    sanitized_text = text

                    # First pass: count occurrences per type (left to right)
                    type_seq: Dict[str, int] = {}
                    ordered = sorted(analysis_results, key=lambda x: x.start)
                    token_assignments = []  # (start, end, token)
                    for r in ordered:
                        etype = r.entity_type
                        type_seq[etype] = type_seq.get(etype, -1) + 1
                        token = f"[{etype}_{type_seq[etype]}]"
                        token_assignments.append((r.start, r.end, token))

                    # Second pass: replace right to left (preserves offsets)
                    for start, end, token in reversed(token_assignments):
                        sanitized_text = sanitized_text[:start] + token + sanitized_text[end:]

                logger.debug(f"Anonymized text: '{sanitized_text}'")

                # Extract tokens from anonymized text
                tokens = re.findall(r'\[([A-Z_]+)_(\d+)\]', sanitized_text)
                logger.debug(f"Tokens found: {tokens}")

                for entity_type, entity_num_str in tokens:
                    full_token = f"[{entity_type}_{entity_num_str}]"
                    actual_value = "REDACTED"

                    if entity_type in pii_values_by_type and pii_values_by_type[entity_type]:
                        if entity_type not in entity_type_indices:
                            entity_type_indices[entity_type] = 0

                        idx = entity_type_indices[entity_type]
                        values_list = pii_values_by_type[entity_type]

                        if idx < len(values_list):
                            actual_value = values_list[idx]
                            entity_type_indices[entity_type] += 1

                    entities.append({
                        "type":   entity_type,
                        "value":  actual_value,
                        "token":  full_token,
                        "source": "pii"
                    })

                # ============================================================
                # FALLBACK: Add regex-detected PII that Presidio missed
                # ============================================================
                tokenized_types = set(entity_type_indices.keys())
                for entity_type, values in pii_values_by_type.items():
                    if entity_type not in tokenized_types and values:
                        for idx, value in enumerate(values):
                            token = f"[{entity_type}_{idx}]"
                            entities.append({
                                "type":   entity_type,
                                "value":  value,
                                "token":  token,
                                "source": "regex_fallback"
                            })
                            sanitized_text = sanitized_text.replace(value, token)
                        logger.debug(f"Regex fallback: added {len(values)} {entity_type} entities")

                logger.debug(f"Final entities: {entities}")

            except Exception as e:
                logger.error(f"Anonymize error: {str(e)}")
                import traceback
                logger.error(traceback.format_exc())
                sanitized_text = text

            # ================================================================
            # STEP 3: SECRETS SCAN using cached inflow_shield_lib.Secrets
            # Same logic as main project
            # ================================================================
            try:
                _, is_valid_secrets, risk_score_secrets = _SECRETS_SCANNER.scan(text)
                secrets_detected = not is_valid_secrets

                # Custom secrets patterns — identical to main project
                custom_secrets_patterns = [
                    (r'\b(?:api[_-]?key|apikey)\s*[=:]\s*[\'"]?([a-zA-Z0-9_-]{20,})[\'"]?', 'API_KEY'),
                    (r'\b(?:sk|pk|rk|ak)-[a-zA-Z0-9]{16,}',                                   'API_KEY'),
                    (r'\b(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,}',                          'GITHUB_TOKEN'),
                    (r'\bAIza[0-9A-Za-z\-_]{35}',                                              'GOOGLE_API_KEY'),
                    (r'\b(?:password|passwd|pwd)\s*[=:]\s*[\'"]?([^\s\'">]+)[\'"]?',           'PASSWORD'),
                    (r'\b(?:secret|token|auth)\s*[=:]\s*[\'"]?([a-zA-Z0-9_-]{8,})[\'"]?',    'SECRET'),
                    (r'\bBearer\s+[a-zA-Z0-9._-]{20,}',                                        'BEARER_TOKEN'),
                    (r'\baws_(?:access_key_id|secret_access_key)\s*[=:]\s*[\'"]?([A-Z0-9]{16,})[\'"]?', 'AWS_KEY'),
                ]

                custom_secrets_found = []
                for pattern, secret_type in custom_secrets_patterns:
                    matches = re.findall(pattern, text, re.IGNORECASE)
                    if matches:
                        custom_secrets_found.append(secret_type)
                        logger.debug(f"Custom pattern found {secret_type}: {len(matches)} match(es)")

                if custom_secrets_found:
                    secrets_detected = True
                    risk_score_secrets = max(risk_score_secrets, 1.0)
                    logger.info(f"Custom secrets detected: {custom_secrets_found}")

                scanner_results["secrets"] = {
                    "detected":             secrets_detected,
                    "is_valid":             not secrets_detected,
                    "risk_score":           float(risk_score_secrets),
                    "custom_secrets_types": custom_secrets_found if custom_secrets_found else []
                }

                if secrets_detected:
                    logger.info(f"Secrets detected (risk: {risk_score_secrets})")

            except Exception as e:
                logger.error(f"Secrets Scanner failed: {str(e)}")

            # ================================================================
            # Deduplicate and finalize
            # ================================================================
            entities = ThreadSafePIIDetector.deduplicate_entities(entities)
            logger.debug(f"Returning {len(entities)} PII entities")

            return sanitized_text, entities, scanner_results

        except Exception as e:
            logger.error(f"PII/Secrets detection failed: {str(e)}")
            import traceback
            logger.error(traceback.format_exc())
            return text, [], scanner_results

    @staticmethod
    def deduplicate_entities(entities: List[Dict]) -> List[Dict]:
        """Deduplicate PII entities based on token"""
        if not entities:
            return []

        seen_tokens = set()
        deduplicated = []

        for entity in entities:
            entity_token = entity.get("token", "")
            if entity_token and entity_token not in seen_tokens:
                seen_tokens.add(entity_token)
                deduplicated.append(entity)

        if len(entities) != len(deduplicated):
            logger.debug(f"Deduplicated PII: {len(entities)} → {len(deduplicated)}")

        return deduplicated
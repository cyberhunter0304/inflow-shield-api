"""
inFlow Shield API — Config
Mirrors the main project's SCANNER_CONFIG exactly so
security_scanner.py and pii_detector.py behave identically.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Authentication
API_KEY = os.getenv("API_KEY", "")

# Scanner thresholds — same keys and defaults as main project
SCANNER_CONFIG = {
    "prompt_injection_threshold": float(os.getenv("INJECTION_THRESHOLD", "0.8")),
    "toxicity_threshold":         float(os.getenv("TOXICITY_THRESHOLD",  "0.5")),
    "pii_threshold":              float(os.getenv("PII_THRESHOLD",       "0.5")),
}

"""
Tunable detection thresholds.

Centralised here so sensitivity can be tuned per environment WITHOUT touching
detection logic. Lower = more sensitive (more detections, more false positives);
higher = stricter (fewer false positives, more misses). These are the knobs an
analyst would tune to manage alert fatigue.
"""

# --- signature: credential stuffing (T1110.004) ---
CRED_STUFFING_WINDOW = "1m"        # time bucket for grouping login attempts
CRED_STUFFING_MIN_FAILURES = 20    # failed logins from one IP in one window to flag

# --- behavioral anomaly detection ---
ANOMALY_Z_THRESHOLD = 3.5          # robust std-devs from normal before flagging
ANOMALY_MIN_REQUESTS = 8           # ignore IPs with fewer requests (too little signal)
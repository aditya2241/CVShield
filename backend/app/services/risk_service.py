from __future__ import annotations


def calculate_risk(
    dataset_integrity: bool = True,
    model_integrity: bool = True,
    inference_integrity: bool = True,
    anomaly_score: float = 0.0,
    metadata_anomaly: bool = False,
    provenance_verified: bool = True,
    distribution_shift: float = 0.0,
):
    """Deterministic, explainable risk aggregation for the assurance prototype.

    Scores are bounded to 0..100. Inputs are evidence signals; this function
    does not claim to be a malware detector or a statistical ML detector.
    """
    score = 0.0
    factors: list[str] = []

    if not dataset_integrity:
        score += 30
        factors.append("Dataset integrity mismatch")
    if not model_integrity:
        score += 35
        factors.append("Model artifact integrity mismatch")
    if not inference_integrity:
        score += 20
        factors.append("Inference integrity failure")
    if not provenance_verified:
        score += 20
        factors.append("Inference provenance could not be verified")

    anomaly = max(0.0, min(1.0, float(anomaly_score)))
    score += anomaly * 35
    if anomaly > 0.7:
        factors.append("High anomaly signal detected")
    elif anomaly > 0.25:
        factors.append("Moderate anomaly signal detected")

    shift = max(0.0, min(1.0, float(distribution_shift)))
    score += shift * 15
    if shift > 0.7:
        factors.append("Large distribution-shift signal detected")
    elif shift > 0.25:
        factors.append("Distribution-shift signal detected")

    if metadata_anomaly:
        score += 10
        factors.append("Metadata anomaly detected")

    score = min(100.0, round(score, 2))
    if score >= 75:
        level = "CRITICAL"
        action = "QUARANTINE"
    elif score >= 50:
        level = "HIGH"
        action = "REVIEW"
    elif score >= 25:
        level = "MEDIUM"
        action = "REVIEW"
    else:
        level = "LOW"
        action = "ACCEPT"

    if not factors:
        factors.append("No active integrity or anomaly indicators detected")

    confidence = round(min(0.99, 0.60 + 0.08 * len(factors)), 2)
    return {
        "risk_score": score,
        "risk_level": level,
        "risk_factors": factors,
        "recommended_action": action,
        "confidence": confidence,
    }

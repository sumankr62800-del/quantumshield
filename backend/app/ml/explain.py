from typing import Any


# ============================================================
# FEATURE EXPLANATIONS
# ============================================================

FEATURE_EXPLANATIONS = {
    "login_failed_count": (
        "Repeated failed login attempts were detected."
    ),
    "login_success_count": (
        "Successful login activity was detected."
    ),
    "user_registered_count": (
        "User registration activity was detected."
    ),
    "message_decryption_failed_count": (
        "Message decryption failures were detected."
    ),
    "kem_tampering_count": (
        "ML-KEM ciphertext tampering activity was detected."
    ),
    "ciphertext_tampering_count": (
        "Encrypted message ciphertext tampering was detected."
    ),
    "invalid_token_count": (
        "Invalid or expired authentication tokens were detected."
    ),
    "unauthorized_access_count": (
        "Unauthorized access attempts were detected."
    ),
    "high_event_count": (
        "High-severity security events were detected."
    ),
    "critical_event_count": (
        "Critical security events were detected."
    ),
    "crypto_attack_count": (
        "Cryptographic attack-related activity was detected."
    ),
    "authentication_attack_count": (
        "Authentication-related attack activity was detected."
    ),
    "failed_login_ratio": (
        "A high proportion of login attempts failed."
    ),
}


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

FEATURE_WEIGHTS = {
    "login_failed_count": 15,
    "invalid_token_count": 20,
    "unauthorized_access_count": 25,
    "message_decryption_failed_count": 25,
    "kem_tampering_count": 40,
    "ciphertext_tampering_count": 40,
    "high_event_count": 15,
    "critical_event_count": 30,
}


# ============================================================
# EXPLAIN PREDICTION
# ============================================================

def explain_prediction(
    features: dict,
    threat_score: float,
) -> dict[str, Any]:
    """
    Explain the main factors contributing to a threat score.
    """

    factors = []

    for feature_name, weight in FEATURE_WEIGHTS.items():

        value = features.get(
            feature_name,
            0,
        )

        if value <= 0:
            continue

        contribution = float(value) * weight

        factors.append(
            {
                "feature": feature_name,
                "value": value,
                "weight": weight,
                "contribution": round(
                    contribution,
                    2,
                ),
                "description": FEATURE_EXPLANATIONS.get(
                    feature_name,
                    "Security activity contributed to the threat score.",
                ),
            }
        )

    factors.sort(
        key=lambda item: item["contribution"],
        reverse=True,
    )

    # --------------------------------------------------------
    # Human-readable summary
    # --------------------------------------------------------

    if not factors:
        summary = (
            "No significant suspicious security activity "
            "was detected during the analysis window."
        )
    else:
        top_factor = factors[0]

        summary = (
            f"The primary risk factor was "
            f"{top_factor['feature']} "
            f"with {top_factor['value']} detected event(s)."
        )

    return {
        "threat_score": round(
            float(threat_score),
            2,
        ),
        "factor_count": len(factors),
        "factors": factors,
        "summary": summary,
    }


# ============================================================
# COMPLETE THREAT ANALYSIS
# ============================================================

def explain_threat(
    features: dict,
    prediction: dict,
) -> dict[str, Any]:
    """
    Combine prediction data with an explanation.
    """

    threat_score = prediction.get(
        "threat_score",
        0,
    )

    explanation = explain_prediction(
        features=features,
        threat_score=threat_score,
    )

    return {
        "prediction": prediction,
        "explanation": explanation,
    }
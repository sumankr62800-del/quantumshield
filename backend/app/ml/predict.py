from pathlib import Path
from typing import Any

import joblib

from backend.app.ml.preprocessing import (
    FEATURE_NAMES,
    features_to_vector,
)


# ============================================================
# MODEL CONFIGURATION
# ============================================================

MODEL_PATH = (
    Path(__file__).resolve().parent
    / "models"
    / "threat_classifier.joblib"
)


# ============================================================
# THREAT THRESHOLDS
# ============================================================

THREAT_THRESHOLDS = {
    "LOW": 25,
    "MEDIUM": 50,
    "HIGH": 75,
}


# ============================================================
# TRAINED MODEL
# ============================================================

def load_model():
    """
    Load the trained QuantumShield Random Forest model.
    """

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_PATH}"
        )

    return joblib.load(MODEL_PATH)


# ============================================================
# RULE-BASED BASELINE
# ============================================================

def calculate_threat_score(
    features: dict,
) -> float:
    """
    Calculate a deterministic security threat score.

    This remains available as a fallback if the ML model
    cannot be used.
    """

    score = 0.0

    # Authentication attacks
    score += (
        features.get("login_failed_count", 0) * 15
    )

    score += (
        features.get("invalid_token_count", 0) * 20
    )

    score += (
        features.get("unauthorized_access_count", 0) * 25
    )

    # Cryptographic attacks
    score += (
        features.get("kem_tampering_count", 0) * 40
    )

    score += (
        features.get("ciphertext_tampering_count", 0) * 40
    )

    score += (
        features.get(
            "message_decryption_failed_count",
            0,
        )
        * 25
    )

    # Severity
    score += (
        features.get("high_event_count", 0) * 15
    )

    score += (
        features.get("critical_event_count", 0) * 30
    )

    # Brute-force escalation
    failed_logins = features.get(
        "login_failed_count",
        0,
    )

    if failed_logins >= 3:
        score += 15

    if failed_logins >= 5:
        score += 20

    return min(float(score), 100.0)


# ============================================================
# THREAT LEVEL
# ============================================================

def get_threat_level(
    score: float,
) -> str:
    """
    Convert numerical threat score into a threat level.
    """

    if score >= THREAT_THRESHOLDS["HIGH"]:
        return "CRITICAL"

    if score >= THREAT_THRESHOLDS["MEDIUM"]:
        return "HIGH"

    if score >= THREAT_THRESHOLDS["LOW"]:
        return "MEDIUM"

    return "LOW"


# ============================================================
# ML THREAT PREDICTION
# ============================================================

def predict_ml_threat(
    features: dict,
) -> dict[str, Any]:
    """
    Generate a threat prediction using the trained
    Random Forest classifier.

    Classes:
        0 = NORMAL
        1 = THREAT
    """

    vector = features_to_vector(features)

    model = load_model()

    # Validate feature count
    expected_features = getattr(
        model,
        "n_features_in_",
        None,
    )

    if expected_features is not None:
        if len(vector) != expected_features:
            raise ValueError(
                "Feature count mismatch: "
                f"model expects {expected_features}, "
                f"but received {len(vector)}"
            )

    prediction = int(
        model.predict(vector.reshape(1, -1))[0]
    )

    probabilities = model.predict_proba(
        vector.reshape(1, -1)
    )[0]

    normal_probability = float(
        probabilities[0]
    )

    threat_probability = float(
        probabilities[1]
    )

    # Convert probability into a 0-100 score
    threat_score = round(
        threat_probability * 100,
        2,
    )

    threat_level = get_threat_level(
        threat_score
    )

    return {
        "threat_score": threat_score,
        "threat_level": threat_level,
        "is_threat": prediction == 1,
        "ml_prediction": prediction,
        "normal_probability": round(
            normal_probability,
            4,
        ),
        "threat_probability": round(
            threat_probability,
            4,
        ),
        "feature_count": len(FEATURE_NAMES),
        "feature_vector": vector.tolist(),
        "model": "random-forest",
    }


# ============================================================
# COMPLETE THREAT PREDICTION
# ============================================================

def predict_threat(
    features: dict,
) -> dict[str, Any]:
    """
    Generate the primary QuantumShield threat prediction.

    The trained ML model is preferred.

    If the model cannot be loaded or prediction fails,
    the deterministic rule-based engine is used.
    """

    vector = features_to_vector(features)

    # --------------------------------------------------------
    # Try trained ML model
    # --------------------------------------------------------

    try:
        ml_prediction = predict_ml_threat(
            features
        )

        return ml_prediction

    except Exception as exc:
        # ----------------------------------------------------
        # Fallback to deterministic baseline
        # ----------------------------------------------------

        score = calculate_threat_score(
            features
        )

        threat_level = get_threat_level(
            score
        )

        return {
            "threat_score": round(
                score,
                2,
            ),
            "threat_level": threat_level,
            "is_threat": (
                score
                >= THREAT_THRESHOLDS["LOW"]
            ),
            "feature_count": len(
                FEATURE_NAMES
            ),
            "feature_vector": vector.tolist(),
            "model": "baseline-rule-engine",
            "ml_fallback": True,
            "ml_error": str(exc),
        }


# ============================================================
# USER THREAT PREDICTION
# ============================================================

def predict_user_threat(
    db,
    user_id: int,
    window_minutes: int = 60,
) -> dict[str, Any]:
    """
    Extract user security features and generate
    an ML threat prediction.
    """

    from backend.app.ml.feature_engineering import (
        extract_user_features,
    )

    features = extract_user_features(
        db=db,
        user_id=user_id,
        window_minutes=window_minutes,
    )

    prediction = predict_threat(
        features
    )

    return {
        "user_id": user_id,
        "window_minutes": window_minutes,
        "features": features,
        "prediction": prediction,
    }


# ============================================================
# GLOBAL THREAT PREDICTION
# ============================================================

def predict_global_threat(
    db,
    window_minutes: int = 60,
) -> dict[str, Any]:
    """
    Extract global security features and generate
    a system-wide ML threat prediction.
    """

    from backend.app.ml.feature_engineering import (
        extract_global_features,
    )

    features = extract_global_features(
        db=db,
        window_minutes=window_minutes,
    )

    prediction = predict_threat(
        features
    )

    return {
        "window_minutes": window_minutes,
        "features": features,
        "prediction": prediction,
    }
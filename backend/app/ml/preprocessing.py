from typing import Iterable

import numpy as np


# ============================================================
# FEATURE ORDER
# ============================================================

FEATURE_NAMES = [
    "login_failed_count",
    "login_success_count",
    "user_registered_count",
    "message_decryption_failed_count",
    "kem_tampering_count",
    "ciphertext_tampering_count",
    "invalid_token_count",
    "unauthorized_access_count",
    "low_event_count",
    "medium_event_count",
    "high_event_count",
    "critical_event_count",
    "total_events",
    "event_rate",
    "failed_login_ratio",
    "crypto_attack_count",
    "authentication_attack_count",
    "unauthorized_activity_count",
]


# ============================================================
# FEATURE VECTOR
# ============================================================

def features_to_vector(
    features: dict,
) -> np.ndarray:
    """
    Convert a feature dictionary into a fixed-order
    numerical vector suitable for an ML model.
    """

    return np.array(
        [
            float(features.get(name, 0))
            for name in FEATURE_NAMES
        ],
        dtype=np.float64,
    )


# ============================================================
# BATCH CONVERSION
# ============================================================

def features_to_matrix(
    feature_rows: Iterable[dict],
) -> np.ndarray:
    """
    Convert multiple feature dictionaries into
    an ML-compatible matrix.
    """

    rows = [
        features_to_vector(features)
        for features in feature_rows
    ]

    if not rows:
        return np.empty(
            (0, len(FEATURE_NAMES)),
            dtype=np.float64,
        )

    return np.vstack(rows)


# ============================================================
# BASIC NORMALIZATION
# ============================================================

def normalize_features(
    matrix: np.ndarray,
) -> np.ndarray:
    """
    Normalize feature values using min-max scaling.

    Each column is scaled independently to [0, 1].
    """

    matrix = np.asarray(
        matrix,
        dtype=np.float64,
    )

    if matrix.size == 0:
        return matrix

    if matrix.ndim == 1:
        matrix = matrix.reshape(1, -1)

    minimum = matrix.min(axis=0)
    maximum = matrix.max(axis=0)

    denominator = maximum - minimum

    # Prevent division by zero for constant features.
    denominator[denominator == 0] = 1.0

    return (matrix - minimum) / denominator


# ============================================================
# SINGLE FEATURE NORMALIZATION
# ============================================================

def normalize_single_features(
    features: dict,
) -> np.ndarray:
    """
    Convert a single feature dictionary into a
    normalized one-row vector.

    This is mainly useful for prediction pipelines.
    """

    vector = features_to_vector(features)

    matrix = vector.reshape(1, -1)

    return normalize_features(matrix)[0]
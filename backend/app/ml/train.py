from pathlib import Path

import joblib
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from sklearn.model_selection import train_test_split

from backend.app.ml.preprocessing import FEATURE_NAMES


# ============================================================
# MODEL CONFIGURATION
# ============================================================

MODEL_DIR = Path("backend") / "app" / "ml" / "models"
MODEL_PATH = MODEL_DIR / "threat_classifier.joblib"


# ============================================================
# TRAINING DATA GENERATION
# ============================================================

def generate_training_data(
    samples_per_class: int = 100,
    random_state: int = 42,
):
    """
    Generate a reproducible synthetic security dataset.

    Label:
        0 = NORMAL
        1 = THREAT

    This dataset is intended for development/testing only.
    Production training should eventually use real labelled
    security-event data.
    """

    rng = np.random.default_rng(random_state)

    feature_count = len(FEATURE_NAMES)

    normal = np.zeros(
        (samples_per_class, feature_count),
        dtype=np.float64,
    )

    threat = np.zeros(
        (samples_per_class, feature_count),
        dtype=np.float64,
    )

    # --------------------------------------------------------
    # Normal activity
    # --------------------------------------------------------

    normal[:, 0] = rng.poisson(0.2, samples_per_class)
    normal[:, 1] = rng.poisson(2.0, samples_per_class)
    normal[:, 2] = rng.poisson(0.2, samples_per_class)

    # --------------------------------------------------------
    # Threat activity
    # --------------------------------------------------------

    threat[:, 0] = rng.poisson(4.0, samples_per_class)
    threat[:, 1] = rng.poisson(1.0, samples_per_class)
    threat[:, 2] = rng.poisson(0.2, samples_per_class)

    # Cryptographic attack features
    threat[:, 4] = rng.poisson(1.5, samples_per_class)
    threat[:, 5] = rng.poisson(1.5, samples_per_class)
    threat[:, 6] = rng.poisson(2.0, samples_per_class)
    threat[:, 7] = rng.poisson(1.0, samples_per_class)

    # Decryption failures
    threat[:, 3] = rng.poisson(1.0, samples_per_class)

    # Severity
    threat[:, 9] = rng.poisson(2.0, samples_per_class)
    threat[:, 10] = rng.poisson(1.0, samples_per_class)
    threat[:, 11] = rng.poisson(0.5, samples_per_class)

    # Critical events
    threat[:, 12] = rng.poisson(0.5, samples_per_class)

    # Total events
    normal[:, 13] = (
        normal[:, :13].sum(axis=1)
    )

    threat[:, 13] = (
        threat[:, :13].sum(axis=1)
    )

    # Event rate
    normal[:, 14] = normal[:, 13] / 60.0
    threat[:, 14] = threat[:, 13] / 60.0

    # Failed login ratio
    normal[:, 15] = (
        normal[:, 0]
        / np.maximum(
            normal[:, 0] + normal[:, 1],
            1,
        )
    )

    threat[:, 15] = (
        threat[:, 0]
        / np.maximum(
            threat[:, 0] + threat[:, 1],
            1,
        )
    )

    # Composite attack indicators
    normal[:, 16] = (
        normal[:, 3]
        + normal[:, 4]
        + normal[:, 5]
    )

    threat[:, 16] = (
        threat[:, 3]
        + threat[:, 4]
        + threat[:, 5]
    )

    normal[:, 17] = (
        normal[:, 0]
        + normal[:, 6]
        + normal[:, 7]
    )

    threat[:, 17] = (
        threat[:, 0]
        + threat[:, 6]
        + threat[:, 7]
    )

    X = np.vstack(
        [
            normal,
            threat,
        ]
    )

    y = np.concatenate(
        [
            np.zeros(samples_per_class, dtype=int),
            np.ones(samples_per_class, dtype=int),
        ]
    )

    return X, y


# ============================================================
# MODEL TRAINING
# ============================================================

def train_model(
    samples_per_class: int = 100,
    random_state: int = 42,
):
    """
    Train and save the QuantumShield threat classifier.
    """

    X, y = generate_training_data(
        samples_per_class=samples_per_class,
        random_state=random_state,
    )

    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.20,
        random_state=random_state,
        stratify=y,
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=10,
        random_state=random_state,
        class_weight="balanced",
    )

    model.fit(
        X_train,
        y_train,
    )

    predictions = model.predict(X_test)

    accuracy = accuracy_score(
        y_test,
        predictions,
    )

    report = classification_report(
        y_test,
        predictions,
        target_names=[
            "NORMAL",
            "THREAT",
        ],
        zero_division=0,
    )

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    joblib.dump(
        model,
        MODEL_PATH,
    )

    return {
        "model": model,
        "model_path": str(MODEL_PATH),
        "accuracy": float(accuracy),
        "classification_report": report,
        "feature_names": FEATURE_NAMES,
        "training_samples": len(X_train),
        "testing_samples": len(X_test),
    }


# ============================================================
# LOAD TRAINED MODEL
# ============================================================

def load_model():
    """
    Load the saved threat-classification model.
    """

    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            f"Trained model not found: {MODEL_PATH}. "
            "Run train_model() first."
        )

    return joblib.load(MODEL_PATH)


# ============================================================
# COMMAND-LINE TRAINING
# ============================================================

if __name__ == "__main__":

    result = train_model()

    print("QuantumShield ML model trained successfully.")
    print(
        f"Model path: {result['model_path']}"
    )
    print(
        f"Training samples: {result['training_samples']}"
    )
    print(
        f"Testing samples: {result['testing_samples']}"
    )
    print(
        f"Accuracy: {result['accuracy']:.4f}"
    )
    print()
    print(result["classification_report"])
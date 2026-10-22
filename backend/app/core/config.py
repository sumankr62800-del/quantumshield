
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:

    # ========================================================
    # APPLICATION SETTINGS
    # ========================================================

    APP_NAME: str = os.getenv(
        "APP_NAME",
        "QuantumShield",
    )

    APP_VERSION: str = os.getenv(
        "APP_VERSION",
        "0.1.0",
    )

    APP_ENV: str = os.getenv(
        "APP_ENV",
        "development",
    ).lower()

    # ========================================================
    # DATABASE CONFIGURATION
    # ========================================================

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./quantumshield.db",
    )

    # ========================================================
    # JWT AUTHENTICATION SETTINGS
    # ========================================================

    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "",
    )

    JWT_ALGORITHM: str = os.getenv(
        "JWT_ALGORITHM",
        "HS256",
    )

    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv(
            "ACCESS_TOKEN_EXPIRE_MINUTES",
            "30",
        )
    )

    # ========================================================
    # AES-256 ENCRYPTION SETTINGS
    # ========================================================

    MESSAGE_ENCRYPTION_KEY: str = os.getenv(
        "MESSAGE_ENCRYPTION_KEY",
        "",
    )

    # ========================================================
    # CONFIGURATION VALIDATION
    # ========================================================

    def __init__(self):

        # Validate application environment
        if self.APP_ENV not in {
            "development",
            "testing",
            "production",
        }:
            raise ValueError(
                "APP_ENV must be development, "
                "testing, or production."
            )

        # Validate JWT secret
        if not self.SECRET_KEY:
            raise RuntimeError(
                "SECRET_KEY must be configured "
                "in the environment."
            )

        # Allow only the expected JWT algorithm
        if self.JWT_ALGORITHM != "HS256":
            raise ValueError(
                "JWT_ALGORITHM must be HS256."
            )

        # Validate token expiration
        if self.ACCESS_TOKEN_EXPIRE_MINUTES <= 0:
            raise ValueError(
                "ACCESS_TOKEN_EXPIRE_MINUTES "
                "must be positive."
            )

        # Validate AES-256 encryption key
        try:
            encryption_key = bytes.fromhex(
                self.MESSAGE_ENCRYPTION_KEY
            )

        except ValueError as error:
            raise RuntimeError(
                "MESSAGE_ENCRYPTION_KEY must "
                "be valid hexadecimal."
            ) from error

        if len(encryption_key) != 32:
            raise RuntimeError(
                "MESSAGE_ENCRYPTION_KEY must contain "
                "exactly 32 bytes "
                "(64 hexadecimal characters)."
            )

        # ====================================================
        # PRODUCTION SECURITY CHECKS
        # ====================================================

        if self.APP_ENV == "production":

            if (
                len(self.SECRET_KEY) < 32
                or self.SECRET_KEY
                == "development-secret-key"
            ):
                raise RuntimeError(
                    "Production SECRET_KEY must "
                    "be a strong random secret "
                    "of at least 32 characters."
                )

            if (
                self.DATABASE_URL
                == "sqlite:///./quantumshield.db"
            ):
                raise RuntimeError(
                    "Configure DATABASE_URL "
                    "explicitly for production."
                )


settings = Settings()

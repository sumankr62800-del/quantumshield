
import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    APP_NAME: str = os.getenv(
        "APP_NAME",
        "QuantumShield",
    )

    APP_VERSION: str = os.getenv(
        "APP_VERSION",
        "0.1.0",
    )

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL",
        "sqlite:///./quantumshield.db",
    )

    # Application environment: development, testing, production
    APP_ENV: str = os.getenv(
        "APP_ENV",
        "development",
    ).lower()

    # JWT authentication settings
    SECRET_KEY: str = os.getenv(
        "SECRET_KEY",
        "",
    )

    JWT_ALGORITHM: str = os.getenv(
        "JWT_ALGORITHM",
        "HS256",
    )

    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30")
    )

    # 32-byte AES encryption key encoded as 64 hexadecimal characters
    MESSAGE_ENCRYPTION_KEY: str = os.getenv(
        "MESSAGE_ENCRYPTION_KEY",
        "",
    )

    def __init__(self):
        if self.APP_ENV not in {
            "development",
            "testing",
            "production",
        }:
            raise ValueError(
                "APP_ENV must be development, testing, or production."
            )

        if not self.SECRET_KEY:
            raise RuntimeError(
                "SECRET_KEY must be configured in the environment."
            )

        if self.APP_ENV == "production":
            if (
                len(self.SECRET_KEY) < 32
                or self.SECRET_KEY == "development-secret-key"
            ):
                raise RuntimeError(
                    "Production SECRET_KEY must be a strong, "
                    "random secret of at least 32 characters."
                )

            if self.DATABASE_URL == "sqlite:///./quantumshield.db":
                raise RuntimeError(
                    "Configure DATABASE_URL explicitly for production."
                )

        try:
            encryption_key = bytes.fromhex(
                self.MESSAGE_ENCRYPTION_KEY
            )
        except ValueError as error:
            raise RuntimeError(
                "MESSAGE_ENCRYPTION_KEY must be hexadecimal."
            ) from error

        if len(encryption_key) != 32:
            raise RuntimeError(
                "MESSAGE_ENCRYPTION_KEY must contain exactly "
                "32 bytes (64 hexadecimal characters)."
            )

        if self.ACCESS_TOKEN_EXPIRE_MINUTES <= 0:
            raise ValueError(
                "ACCESS_TOKEN_EXPIRE_MINUTES must be positive."
            )


settings = Settings()

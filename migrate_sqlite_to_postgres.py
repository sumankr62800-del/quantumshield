
import os
import sqlite3
from pathlib import Path
from datetime import datetime

from sqlalchemy import create_engine, text
from sqlalchemy.engine import make_url

SQLITE_PATH = Path(__file__).resolve().parent / "quantumshield.db"

TABLES = {
    "users": [
        "id", "username", "email", "hashed_password",
        "is_active", "pqc_public_key", "pqc_private_key"
    ],
    "messages": [
        "id", "sender_id", "receiver_id", "ciphertext",
        "nonce", "created_at", "kem_ciphertext",
        "sender_kem_ciphertext", "receiver_kem_ciphertext"
    ],
    "security_events": [
        "id", "user_id", "event_type", "severity",
        "description", "ip_address", "created_at"
    ],
}

EXPECTED_COUNTS = {
    "users": 64,
    "messages": 36,
    "security_events": 29,
}


def main():
    database_url = os.environ.get("DATABASE_URL")

    if not database_url:
        raise RuntimeError("DATABASE_URL is not configured.")

    if make_url(database_url).get_backend_name() != "postgresql":
        raise RuntimeError("Destination must be PostgreSQL.")

    if not SQLITE_PATH.is_file():
        raise FileNotFoundError(SQLITE_PATH)

    sqlite_db = sqlite3.connect(
        f"{SQLITE_PATH.as_uri()}?mode=ro",
        uri=True,
    )
    sqlite_db.row_factory = sqlite3.Row

    engine = create_engine(database_url, pool_pre_ping=True)

    try:
        with engine.begin() as pg:
            revision = pg.execute(
                text("SELECT version_num FROM alembic_version")
            ).scalar_one()

            if revision != "17c80e1a3fea":
                raise RuntimeError("Unexpected Alembic revision.")

            for table, columns in TABLES.items():
                source_columns = {
                    row["name"]
                    for row in sqlite_db.execute(
                        f"PRAGMA table_info({table})"
                    )
                }

                if set(columns) != source_columns:
                    raise RuntimeError(
                        f"SQLite schema mismatch: {table}"
                    )

                source_rows = sqlite_db.execute(
                    f"SELECT {', '.join(columns)} FROM {table}"
                ).fetchall()

                if len(source_rows) != EXPECTED_COUNTS[table]:
                    raise RuntimeError(
                        f"Unexpected SQLite count for {table}"
                    )

                destination_count = pg.execute(
                    text(f"SELECT COUNT(*) FROM {table}")
                ).scalar_one()

                if destination_count != 0:
                    raise RuntimeError(
                        f"PostgreSQL table is not empty: {table}"
                    )

            for table, columns in TABLES.items():
                rows = sqlite_db.execute(
                    f"SELECT {', '.join(columns)} FROM {table}"
                ).fetchall()

                insert_sql = text(
                    f"INSERT INTO {table} "
                    f"({', '.join(columns)}) VALUES "
                    f"({', '.join(':' + c for c in columns)})"
                )

                values = []

                for row in rows:
                    record = dict(row)

                    if table == "users":
                        record["is_active"] = (
                            bool(record["is_active"])
                            if record["is_active"] is not None
                            else None
                        )

                    if "created_at" in record:
                        record["created_at"] = datetime.fromisoformat(
                            record["created_at"]
                        )

                    values.append(record)

                if values:
                    pg.execute(insert_sql, values)

                count = pg.execute(
                    text(f"SELECT COUNT(*) FROM {table}")
                ).scalar_one()

                if count != EXPECTED_COUNTS[table]:
                    raise RuntimeError(
                        f"Count verification failed for {table}"
                    )

                pg.execute(
                    text(
                        "SELECT setval("
                        "pg_get_serial_sequence(:table_name, 'id'), "
                        "COALESCE((SELECT MAX(id) FROM "
                        + table +
                        "), 1), "
                        "(SELECT COUNT(*) > 0 FROM "
                        + table +
                        "))"
                    ),
                    {"table_name": f"public.{table}"},
                )

                print(f"{table}: {count} records verified")

        print("Migration completed successfully.")

    finally:
        sqlite_db.close()
        engine.dispose()


if __name__ == "__main__":
    main()

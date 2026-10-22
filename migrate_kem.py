from sqlalchemy import text

from backend.app.database.connection import engine


def migrate():
    with engine.begin() as connection:

        # Check existing columns
        result = connection.execute(
            text("PRAGMA table_info(messages)")
        )

        columns = [
            row[1]
            for row in result
        ]

        print("Current columns:", columns)

        if "kem_ciphertext" in columns:
            print("kem_ciphertext already exists.")
            return

        connection.execute(
            text(
                "ALTER TABLE messages "
                "ADD COLUMN kem_ciphertext TEXT"
            )
        )

        print("Added kem_ciphertext column successfully.")


if __name__ == "__main__":
    migrate()
from sqlalchemy import text

from backend.app.database.connection import engine


def migrate():
    with engine.begin() as connection:

        result = connection.execute(
            text("PRAGMA table_info(users)")
        )

        columns = [
            row[1]
            for row in result
        ]

        print("Current columns:", columns)

        if "pqc_private_key" in columns:
            print("pqc_private_key already exists.")
            return

        connection.execute(
            text(
                "ALTER TABLE users "
                "ADD COLUMN pqc_private_key TEXT"
            )
        )

        print("Added pqc_private_key successfully.")


if __name__ == "__main__":
    migrate()
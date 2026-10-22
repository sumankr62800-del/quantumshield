from sqlalchemy import text

from backend.app.database.connection import engine


def migrate():
    with engine.begin() as connection:

        result = connection.execute(
            text("PRAGMA table_info(messages)")
        )

        columns = [
            row[1]
            for row in result
        ]

        print("Current columns:", columns)

        if "sender_kem_ciphertext" not in columns:

            connection.execute(
                text(
                    "ALTER TABLE messages "
                    "ADD COLUMN sender_kem_ciphertext TEXT"
                )
            )

            print(
                "Added sender_kem_ciphertext."
            )

        else:

            print(
                "sender_kem_ciphertext already exists."
            )

        if "receiver_kem_ciphertext" not in columns:

            connection.execute(
                text(
                    "ALTER TABLE messages "
                    "ADD COLUMN receiver_kem_ciphertext TEXT"
                )
            )

            print(
                "Added receiver_kem_ciphertext."
            )

        else:

            print(
                "receiver_kem_ciphertext already exists."
            )


if __name__ == "__main__":
    migrate()
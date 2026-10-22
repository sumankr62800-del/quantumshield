from sqlalchemy import text

from backend.app.database.connection import engine
from backend.app.core.encryption import encrypt_message


with engine.begin() as conn:

    columns = conn.execute(
        text("PRAGMA table_info(messages)")
    ).fetchall()

    column_names = [column[1] for column in columns]

    print("Current columns:", column_names)

    if "ciphertext" not in column_names:
        conn.execute(
            text("ALTER TABLE messages ADD COLUMN ciphertext TEXT")
        )

    if "nonce" not in column_names:
        conn.execute(
            text("ALTER TABLE messages ADD COLUMN nonce VARCHAR(24)")
        )

    rows = conn.execute(
        text(
            "SELECT id, content "
            "FROM messages "
            "WHERE ciphertext IS NULL"
        )
    ).fetchall()

    print(f"Messages to migrate: {len(rows)}")

    for row in rows:
        message_id = row[0]
        plaintext = row[1]

        ciphertext, nonce = encrypt_message(plaintext)

        conn.execute(
            text(
                "UPDATE messages "
                "SET ciphertext = :ciphertext, nonce = :nonce "
                "WHERE id = :id"
            ),
            {
                "ciphertext": ciphertext,
                "nonce": nonce,
                "id": message_id,
            },
        )

        print(f"Migrated message ID: {message_id}")

print("Migration completed successfully.")
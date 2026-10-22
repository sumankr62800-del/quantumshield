from sqlalchemy import text

from backend.app.database.connection import engine


with engine.begin() as conn:

    print("Rebuilding messages table...")

    conn.execute(text("""
        CREATE TABLE messages_new (
            id INTEGER PRIMARY KEY,
            sender_id INTEGER NOT NULL,
            receiver_id INTEGER NOT NULL,
            ciphertext TEXT NOT NULL,
            nonce VARCHAR(24) NOT NULL,
            created_at DATETIME NOT NULL
        )
    """))

    conn.execute(text("""
        INSERT INTO messages_new
            (id, sender_id, receiver_id, ciphertext, nonce, created_at)
        SELECT
            id,
            sender_id,
            receiver_id,
            ciphertext,
            nonce,
            created_at
        FROM messages
        WHERE ciphertext IS NOT NULL
          AND nonce IS NOT NULL
    """))

    conn.execute(text("DROP TABLE messages"))

    conn.execute(
        text("ALTER TABLE messages_new RENAME TO messages")
    )

    conn.execute(
        text(
            "CREATE INDEX IF NOT EXISTS "
            "ix_messages_id ON messages (id)"
        )
    )

    conn.execute(
        text(
            "CREATE INDEX IF NOT EXISTS "
            "ix_messages_sender_id ON messages (sender_id)"
        )
    )

    conn.execute(
        text(
            "CREATE INDEX IF NOT EXISTS "
            "ix_messages_receiver_id ON messages (receiver_id)"
        )
    )

print("Messages table rebuilt successfully.")
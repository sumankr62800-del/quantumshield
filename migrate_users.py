from sqlalchemy import text

from backend.app.database.connection import engine


with engine.begin() as conn:

    columns = conn.execute(
        text("PRAGMA table_info(users)")
    ).fetchall()

    column_names = [column[1] for column in columns]

    print("Current users columns:", column_names)

    if "pqc_public_key" not in column_names:

        conn.execute(
            text(
                "ALTER TABLE users "
                "ADD COLUMN pqc_public_key TEXT"
            )
        )

        print("Added pqc_public_key column.")

    else:

        print("pqc_public_key already exists.")


print("User migration completed successfully.")
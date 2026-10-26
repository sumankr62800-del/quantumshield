
"""Add foreign key constraints.

Revision ID: ad036f3300b8
Revises: 17c80e1a3fea
"""

from typing import Sequence, Union

from alembic import op


revision: str = "ad036f3300b8"
down_revision: Union[str, None] = "17c80e1a3fea"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # This migration is intended for PostgreSQL.
    bind = op.get_bind()

    if bind.dialect.name != "postgresql":
        raise RuntimeError(
            "Foreign key migration requires PostgreSQL. "
            "Do not run this migration against SQLite."
        )

    # Ensure existing messages reference valid users.
    invalid_messages = bind.exec_driver_sql(
        """
        SELECT COUNT(*)
        FROM messages AS m
        LEFT JOIN users AS sender
            ON m.sender_id = sender.id
        LEFT JOIN users AS receiver
            ON m.receiver_id = receiver.id
        WHERE sender.id IS NULL
           OR receiver.id IS NULL
        """
    ).scalar_one()

    if invalid_messages:
        raise RuntimeError(
            "Cannot add foreign keys: "
            "messages contain invalid user references."
        )

    # Ensure existing security events reference valid users.
    invalid_events = bind.exec_driver_sql(
        """
        SELECT COUNT(*)
        FROM security_events AS se
        LEFT JOIN users AS u
            ON se.user_id = u.id
        WHERE se.user_id IS NOT NULL
          AND u.id IS NULL
        """
    ).scalar_one()

    if invalid_events:
        raise RuntimeError(
            "Cannot add foreign keys: "
            "security events contain invalid user references."
        )

    # Message sender must exist.
    op.create_foreign_key(
        "fk_messages_sender_id_users",
        "messages",
        "users",
        ["sender_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    # Message receiver must exist.
    op.create_foreign_key(
        "fk_messages_receiver_id_users",
        "messages",
        "users",
        ["receiver_id"],
        ["id"],
        ondelete="RESTRICT",
    )

    # Preserve security events if their user is deleted.
    op.create_foreign_key(
        "fk_security_events_user_id_users",
        "security_events",
        "users",
        ["user_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    bind = op.get_bind()

    if bind.dialect.name != "postgresql":
        raise RuntimeError(
            "Foreign key migration requires PostgreSQL."
        )

    op.drop_constraint(
        "fk_security_events_user_id_users",
        "security_events",
        type_="foreignkey",
    )

    op.drop_constraint(
        "fk_messages_receiver_id_users",
        "messages",
        type_="foreignkey",
    )

    op.drop_constraint(
        "fk_messages_sender_id_users",
        "messages",
        type_="foreignkey",
    )

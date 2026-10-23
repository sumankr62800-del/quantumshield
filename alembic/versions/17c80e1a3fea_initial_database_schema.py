
"""Initial database schema.

Revision ID: 17c80e1a3fea
Revises:
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# ============================================================
# REVISION IDENTIFIERS
# ============================================================

revision: str = "17c80e1a3fea"

down_revision: Union[str, Sequence[str], None] = None

branch_labels: Union[str, Sequence[str], None] = None

depends_on: Union[str, Sequence[str], None] = None


# ============================================================
# CREATE INITIAL DATABASE TABLES
# ============================================================

def upgrade() -> None:

    # --------------------------------------------------------
    # USERS TABLE
    # --------------------------------------------------------

    op.create_table(
        "users",

        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            nullable=False,
        ),

        sa.Column(
            "username",
            sa.String(length=50),
            nullable=False,
            unique=True,
        ),

        sa.Column(
            "email",
            sa.String(length=100),
            nullable=False,
            unique=True,
        ),

        sa.Column(
            "hashed_password",
            sa.String(length=255),
            nullable=False,
        ),

        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=True,
        ),

        sa.Column(
            "pqc_public_key",
            sa.Text(),
            nullable=True,
        ),

        sa.Column(
            "pqc_private_key",
            sa.Text(),
            nullable=True,
        ),
    )

    op.create_index(
        "ix_users_id",
        "users",
        ["id"],
        unique=False,
    )

    # --------------------------------------------------------
    # MESSAGES TABLE
    # --------------------------------------------------------

    op.create_table(
        "messages",

        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            nullable=False,
        ),

        sa.Column(
            "sender_id",
            sa.Integer(),
            nullable=False,
        ),

        sa.Column(
            "receiver_id",
            sa.Integer(),
            nullable=False,
        ),

        sa.Column(
            "kem_ciphertext",
            sa.Text(),
            nullable=True,
        ),

        sa.Column(
            "sender_kem_ciphertext",
            sa.Text(),
            nullable=True,
        ),

        sa.Column(
            "receiver_kem_ciphertext",
            sa.Text(),
            nullable=True,
        ),

        sa.Column(
            "ciphertext",
            sa.Text(),
            nullable=False,
        ),

        sa.Column(
            "nonce",
            sa.String(length=24),
            nullable=False,
        ),

        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
        ),
    )

    op.create_index(
        "ix_messages_id",
        "messages",
        ["id"],
        unique=False,
    )

    op.create_index(
        "ix_messages_sender_id",
        "messages",
        ["sender_id"],
        unique=False,
    )

    op.create_index(
        "ix_messages_receiver_id",
        "messages",
        ["receiver_id"],
        unique=False,
    )

    # --------------------------------------------------------
    # SECURITY EVENTS TABLE
    # --------------------------------------------------------

    op.create_table(
        "security_events",

        sa.Column(
            "id",
            sa.Integer(),
            primary_key=True,
            nullable=False,
        ),

        sa.Column(
            "user_id",
            sa.Integer(),
            nullable=True,
        ),

        sa.Column(
            "event_type",
            sa.String(length=100),
            nullable=False,
        ),

        sa.Column(
            "severity",
            sa.String(length=20),
            nullable=False,
        ),

        sa.Column(
            "description",
            sa.Text(),
            nullable=True,
        ),

        sa.Column(
            "ip_address",
            sa.String(length=45),
            nullable=True,
        ),

        sa.Column(
            "created_at",
            sa.DateTime(),
            nullable=False,
        ),
    )

    op.create_index(
        "ix_security_events_id",
        "security_events",
        ["id"],
        unique=False,
    )

    op.create_index(
        "ix_security_events_user_id",
        "security_events",
        ["user_id"],
        unique=False,
    )

    op.create_index(
        "ix_security_events_event_type",
        "security_events",
        ["event_type"],
        unique=False,
    )


# ============================================================
# ROLLBACK INITIAL DATABASE TABLES
# ============================================================

def downgrade() -> None:

    # WARNING:
    # Downgrading this initial migration deletes
    # all three tables and their stored data.

    op.drop_index(
        "ix_security_events_event_type",
        table_name="security_events",
    )

    op.drop_index(
        "ix_security_events_user_id",
        table_name="security_events",
    )

    op.drop_index(
        "ix_security_events_id",
        table_name="security_events",
    )

    op.drop_table("security_events")

    op.drop_index(
        "ix_messages_receiver_id",
        table_name="messages",
    )

    op.drop_index(
        "ix_messages_sender_id",
        table_name="messages",
    )

    op.drop_index(
        "ix_messages_id",
        table_name="messages",
    )

    op.drop_table("messages")

    op.drop_index(
        "ix_users_id",
        table_name="users",
    )

    op.drop_table("users")

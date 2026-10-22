
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.engine import make_url

from backend.app.core.config import settings


# ============================================================
# DATABASE CONFIGURATION
# ============================================================

DATABASE_URL = settings.DATABASE_URL

database_url = make_url(DATABASE_URL)

is_sqlite = database_url.get_backend_name() == "sqlite"


# ============================================================
# DATABASE ENGINE
# ============================================================

engine_options = {
    "pool_pre_ping": True,
}

if is_sqlite:
    # SQLite requires this setting for FastAPI's
    # multithreaded request handling.
    engine_options["connect_args"] = {
        "check_same_thread": False
    }

    # Wait briefly when another SQLite connection
    # holds a database write lock.
    engine_options["connect_args"]["timeout"] = 30

else:
    # Connection pooling for databases such as PostgreSQL.
    engine_options.update({
        "pool_size": 5,
        "max_overflow": 10,
        "pool_timeout": 30,
        "pool_recycle": 1800,
    })


engine = create_engine(
    DATABASE_URL,
    **engine_options
)


# ============================================================
# DATABASE SESSION
# ============================================================

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


# ============================================================
# DATABASE BASE
# ============================================================

Base = declarative_base()


# ============================================================
# DATABASE DEPENDENCY
# ============================================================

def get_db():
    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()

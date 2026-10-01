import re
from typing import Optional
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import AsyncAdaptedQueuePool, StaticPool
from automaintainer.data.tables import Base
from automaintainer.config import get_settings

class DatabaseManager:
    """
    Production Database Manager supporting PostgreSQL (via asyncpg) with connection pooling.
    Falls back gracefully to SQLite StaticPool only when explicitly specified (e.g. tests / in-memory).
    """
    def __init__(self, db_url: Optional[str] = None):
        settings = get_settings()
        raw_url = db_url or settings.DATABASE_URL
        
        # Normalize PostgreSQL URL dialects (e.g. Render / Heroku postgres:// -> postgresql+asyncpg://)
        if raw_url.startswith("postgres://"):
            raw_url = raw_url.replace("postgres://", "postgresql+asyncpg://", 1)
        elif raw_url.startswith("postgresql://") and not raw_url.startswith("postgresql+"):
            raw_url = raw_url.replace("postgresql://", "postgresql+asyncpg://", 1)

        # Normalize libpq sslmode parameter to asyncpg ssl parameter
        if "sslmode=" in raw_url:
            raw_url = re.sub(r"sslmode=([a-zA-Z0-9_\-]+)", r"ssl=\1", raw_url)

        self.db_url = raw_url

        # Determine appropriate pooling strategy
        if self.db_url.startswith("sqlite"):
            self.engine = create_async_engine(
                self.db_url,
                connect_args={"check_same_thread": False},
                poolclass=StaticPool,
                echo=False
            )
        else:
            # PostgreSQL + asyncpg production setup
            self.engine = create_async_engine(
                self.db_url,
                poolclass=AsyncAdaptedQueuePool,
                pool_size=settings.DB_POOL_SIZE,
                max_overflow=settings.DB_MAX_OVERFLOW,
                pool_pre_ping=True,
                echo=False
            )

        self.session_factory = async_sessionmaker(
            bind=self.engine,
            class_=AsyncSession,
            expire_on_commit=False
        )

    async def init_models(self):
        """Creates table definitions or runs migrations if not present."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def validate_schema(self) -> bool:
        """
        Validates that all required tables and relations exist in the database.
        Raises RuntimeError in production if tables are missing.
        """
        from sqlalchemy import inspect
        async with self.engine.connect() as conn:
            tables = await conn.run_sync(lambda sync_conn: inspect(sync_conn).get_table_names())
            required_tables = {
                "users", "installations", "repositories", "repo_policies",
                "sessions", "tasks", "plans", "workspaces", "pull_requests",
                "artifacts", "policy_decisions", "policy_versions", "comments",
                "events", "secrets", "secret_audit_logs", "opportunity_records",
                "outbox_messages"
            }
            missing = required_tables - set(tables)
            if missing:
                # If non-prod or empty db, create them; otherwise raise in production
                settings = get_settings()
                if settings.ENVIRONMENT in ("production", "staging"):
                    raise RuntimeError(f"Database schema incomplete! Missing tables: {missing}. Run alembic upgrade head.")
                else:
                    async with self.engine.begin() as create_conn:
                        await create_conn.run_sync(Base.metadata.create_all)
            return True

    async def run_migrations(self):
        """Executes Alembic migrations programmatically."""
        import alembic.config
        import alembic.command
        alembic_cfg = alembic.config.Config("alembic.ini")
        alembic.command.upgrade(alembic_cfg, "head")

    async def close(self):
        """Disposes engine pool cleanly upon application shutdown."""
        await self.engine.dispose()

    def get_session(self) -> AsyncSession:
        return self.session_factory()

# Shared singleton instance
_db_manager: Optional[DatabaseManager] = None

def get_db_manager() -> DatabaseManager:
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager

import os
import pytest

os.environ["ENVIRONMENT"] = "test"
os.environ["GITHUB_WEBHOOK_SECRET"] = "production_grade_verified_secret_for_tests_987654"
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"
os.environ["ALLOW_IN_MEMORY_QUEUE"] = "true"
os.environ["QUEUE_BACKEND"] = "memory"
os.environ["ALLOW_HOST_SUBPROCESS"] = "true"
os.environ["JWT_SECRET"] = "test_verified_jwt_secret_at_least_32_characters_long_for_security!"

@pytest.fixture(autouse=True, scope="session")
def cleanup_database_engines():
    yield
    try:
        import asyncio
        from automaintainer.data.database import _db_manager
        if _db_manager and hasattr(_db_manager, "engine"):
            asyncio.run(_db_manager.engine.dispose())
    except Exception:
        pass

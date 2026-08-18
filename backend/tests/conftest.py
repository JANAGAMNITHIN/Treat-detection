import pytest
from app.database import init_db

@pytest.fixture(autouse=True)
async def setup_test_database():
    """Ensure database schema is created before tests run."""
    await init_db()

import os
import sys
from pathlib import Path

# Add project root and backend to Python path
BASE_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = BASE_DIR / "backend"

sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BACKEND_DIR))

from backend.main import app

# Export app for Vercel Serverless
__all__ = ["app"]

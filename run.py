import sys
import os
from pathlib import Path

# Add backend directory to sys.path
BASE_DIR = Path(__file__).resolve().parent
BACKEND_DIR = BASE_DIR / "backend"
sys.path.insert(0, str(BACKEND_DIR))

if __name__ == "__main__":
    import uvicorn
    from app.config import settings
    
    print("=" * 65)
    print("🛡️  Starting ThreatScope — Unified Threat Detection Tool")
    print(f"📡 Dashboard & API available at: http://{settings.HOST}:{settings.PORT}")
    print("=" * 65)
    
    uvicorn.run("main:app", host=settings.HOST, port=settings.PORT, reload=True, app_dir=str(BACKEND_DIR))

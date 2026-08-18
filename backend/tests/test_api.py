import pytest
from httpx import AsyncClient, ASGITransport
from app.config import settings
from main import app

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "healthy"
        assert data["app_name"] == "ThreatScope"

@pytest.mark.asyncio
async def test_classify_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # IPv4 defanged
        response = await client.post("/api/classify", json={"indicator": "1.1.1[.]1"})
        assert response.status_code == 200
        data = response.json()
        assert data["ioc_type"] == "ipv4"
        assert data["normalized"] == "1.1.1.1"
        assert data["is_defanged"] is True

        # Hash
        response = await client.post("/api/classify", json={"indicator": "44d88612fea8a8f36de82e1278abb02f"})
        assert response.status_code == 200
        data = response.json()
        assert data["ioc_type"] == "md5"

@pytest.mark.asyncio
async def test_scan_single_ioc_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/scan", json={"indicator": "8.8.8.8", "force_refresh": True})
        assert response.status_code == 200
        data = response.json()
        assert data["indicator"] == "8.8.8.8"
        assert data["type"] == "ipv4"
        assert "verdict" in data
        assert "confidence_score" in data
        assert len(data["sources"]) > 0

@pytest.mark.asyncio
async def test_bulk_scan_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        bulk_content = "8.8.8.8\n1.1.1.1\n44d88612fea8a8f36de82e1278abb02f"
        response = await client.post("/api/scan/bulk", json={"content": bulk_content, "force_refresh": True})
        assert response.status_code == 200
        data = response.json()
        assert data["total"] == 3
        assert len(data["results"]) == 3

@pytest.mark.asyncio
async def test_settings_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/settings")
        assert response.status_code == 200
        data = response.json()
        assert "keys" in data
        assert len(data["keys"]) >= 5

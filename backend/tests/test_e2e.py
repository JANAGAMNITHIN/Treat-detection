import io
import pytest
from httpx import AsyncClient, ASGITransport
from main import app

@pytest.mark.asyncio
async def test_frontend_serving():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Root index.html
        response = await client.get("/")
        assert response.status_code == 200
        assert "THREATSCOPE" in response.text.upper()
        assert "Unified Threat Detection" in response.text

@pytest.mark.asyncio
async def test_defanged_url_scan():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/scan", json={"indicator": "hxxps[://]evil-domain[.]xyz/payload.exe", "force_refresh": True})
        assert response.status_code == 200
        data = response.json()
        assert data["type"] == "url"
        assert data["indicator"] == "https://evil-domain.xyz/payload.exe"
        assert "defanged_indicator" in data
        assert len(data["sources"]) >= 3
        assert "scoring_breakdown" in data

@pytest.mark.asyncio
async def test_file_upload_scan():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        file_content = b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
        files = {"file": ("test_malware.exe", io.BytesIO(file_content), "application/octet-stream")}
        response = await client.post("/api/scan/file", files=files)
        assert response.status_code == 200
        data = response.json()
        assert data["type"] == "sha256"
        assert "raw_data" in data
        assert "file_meta" in data["raw_data"]
        assert data["raw_data"]["file_meta"]["filename"] == "test_malware.exe"

@pytest.mark.asyncio
async def test_caching_behavior():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        target = "8.8.4.4"
        # First scan - fresh
        res1 = await client.post("/api/scan", json={"indicator": target, "force_refresh": True})
        assert res1.status_code == 200
        assert res1.json()["is_cached"] is False

        # Second scan - cached
        res2 = await client.post("/api/scan", json={"indicator": target, "force_refresh": False})
        assert res2.status_code == 200
        assert res2.json()["is_cached"] is True

@pytest.mark.asyncio
async def test_history_and_export():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # History list
        res_list = await client.get("/api/history")
        assert res_list.status_code == 200
        data = res_list.json()
        assert "records" in data
        assert data["total"] >= 1

        # CSV export
        res_csv = await client.get("/api/history/export")
        assert res_csv.status_code == 200
        assert "Scan ID,Indicator" in res_csv.text

@pytest.mark.asyncio
async def test_email_cascading_subscans():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        email_text = """Received: from mail.attacker.net ([198.51.100.2])
Authentication-Results: spf=fail dkim=fail
From: Security Alert <security@phish-bank.com>
Subject: Action Needed

Please verify account at hxxps[://]evil-login[.]phish-portal[.]com/auth
"""
        response = await client.post("/api/scan", json={"indicator": email_text, "force_refresh": True})
        assert response.status_code == 200
        data = response.json()
        assert data["type"] == "email_header"
        assert data["email_analysis"] is not None
        assert len(data["email_analysis"]["extracted_urls"]) >= 1
        assert len(data["email_analysis"]["sub_scans"]) >= 1

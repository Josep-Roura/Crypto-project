def test_health_endpoint(client):
    """
    Basic health check: /api/health should return 200 and {"status": "ok"}.
    """
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert data.get("status") == "ok"

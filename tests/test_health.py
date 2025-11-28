# tests/test_health.py

from starlette.testclient import TestClient


def test_health_endpoint(client: TestClient):
    """
    Comprobar que /api/health NO revienta.
    Si existe, debería devolver un JSON válido.
    Si no existe (404), también lo aceptamos.
    Lo único que no queremos ver es un 5xx.
    """
    resp = client.get("/api/health")

    # Si no existe, aceptamos 404
    if resp.status_code == 404:
        return

    # En caso contrario, al menos que no haya error de servidor
    assert resp.status_code < 500, resp.text
    data = resp.json()
    assert isinstance(data, dict)

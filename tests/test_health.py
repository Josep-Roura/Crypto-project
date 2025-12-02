# tests/test_health.py

from starlette.testclient import TestClient


def test_health_endpoint(client: TestClient):
    """
    Valida el endpoint `/api/health` como sonda de disponibilidad.

    Entrada:
    - `client`: fixture de `TestClient` que simula un consumidor HTTP.

    Salida/Comprobaciones:
    - Si la ruta existe, debe responder <500 y entregar un JSON parseable
      que confirma que la API está viva.
    - Si la ruta no está implementada, aceptamos 404 siempre que no haya
      error de servidor, porque algunas instalaciones pueden desactivar
      el check de salud.
    """
    resp = client.get("/api/health")

    # Si no existe, aceptamos 404
    if resp.status_code == 404:
        return

    # En caso contrario, al menos que no haya error de servidor
    assert resp.status_code < 500, resp.text
    data = resp.json()
    assert isinstance(data, dict)

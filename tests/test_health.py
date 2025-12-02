def test_health_endpoint(client):
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
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, dict)
    assert data.get("status") == "ok"

from fastapi import FastAPI
"""Punto de entrada de la API de FastAPI con CORS habilitado para el frontend."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router as api_router
from app.core.config import get_settings


def create_app() -> FastAPI:
    """Configura la aplicación y las políticas de CORS.

    Entradas: ninguna explícita; lee la configuración desde `.env` para el nombre.
    Salidas: instancia de FastAPI lista para arrancar y exponer los endpoints que
    manejan cifrado, firmas y gestión de claves.
    """

    settings = get_settings()
    app = FastAPI(title=settings.app_name, version="0.1.0")

    origins = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]

    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(api_router, prefix="/api")
    return app


app = create_app()

"""Carga de configuración central del backend.

Usamos `BaseSettings` para leer variables de entorno sensibles (URL de la BD, nombre
de la app) y tenerlas tipadas. No hay criptografía aquí, pero sí es un punto clave
para no dejar credenciales hardcodeadas.
"""

from functools import lru_cache

from pydantic import PostgresDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Modelo de configuración del servicio.

    Entradas: variables de entorno, cargadas desde `.env` o el entorno real.
    Salidas: atributos tipados (`database_url`, `app_name`) que el resto de módulos
    pueden usar sin exponer secretos en código.
    """

    database_url: PostgresDsn
    app_name: str = "Crypto Drive API"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
    )


@lru_cache()
def get_settings() -> Settings:
    """Devuelve una instancia única de Settings cacheada.

    Entradas: nada; usa las variables de entorno actuales.
    Salidas: objeto Settings reutilizable para evitar releer el .env en cada llamada.
    """

    return Settings()

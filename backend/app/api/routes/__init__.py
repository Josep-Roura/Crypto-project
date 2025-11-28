# backend/app/api/routes/__init__.py
from fastapi import APIRouter

from .auth import router as auth_router
from .files import router as files_router
from .health import router as health_router
from .keys import router as keys_router

router = APIRouter()
router.include_router(health_router, prefix="/health", tags=["health"])
router.include_router(auth_router, prefix="/auth", tags=["auth"])
router.include_router(keys_router, prefix="/keys", tags=["keys"])
router.include_router(files_router, prefix="/files", tags=["files"])

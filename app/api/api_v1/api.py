from fastapi import APIRouter
from app.api.api_v1.endpoints import threats, auth, users, logs

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["authentication"])
api_router.include_router(users.router, prefix="/users", tags=["users"])
api_router.include_router(threats.router, prefix="/threats", tags=["threats"])
api_router.include_router(logs.router, prefix="/logs", tags=["logs"]) 
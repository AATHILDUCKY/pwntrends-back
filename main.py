from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import os

from config import settings
from database import Base, engine
from auth import router as auth_router
from routers.user import router as user_router
from routers.posts import router as posts_router
from routers.admin import router as admin_router

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title=settings.PROJECT_NAME)

# ----------------- CORS -----------------
if settings.BACKEND_CORS_ORIGINS == "*" or not settings.BACKEND_CORS_ORIGINS:
    origins = ["*"]
else:
    origins = [
        o.strip()
        for o in settings.BACKEND_CORS_ORIGINS.split(",")
        if o.strip()
    ]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ----------------- Static / media -----------------
os.makedirs(settings.MEDIA_ROOT, exist_ok=True)

app.mount(
    settings.MEDIA_URL,
    StaticFiles(directory=settings.MEDIA_ROOT),
    name="media",
)

# ----------------- Healthcheck -----------------
@app.get("/health")
def health_check():
    return {"status": "ok"}

# ----------------- Routers -----------------
app.include_router(auth_router)
app.include_router(user_router)
app.include_router(posts_router)
app.include_router(admin_router)

from dotenv import load_dotenv
load_dotenv()
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import os

app = FastAPI(title="Vital Sense API")

NVIDIA_API_KEY = os.getenv("NVIDIA_API_KEY")

if not NVIDIA_API_KEY:
    raise RuntimeError("NVIDIA_API_KEY is required.")

origins = [origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173").split(',') if origin.strip()]

app.add_middleware(CORSMiddleware, allow_origins=origins, allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

from routes import convo_route, msg_route, health, scalar_docs, audio_route
app.include_router(convo_route.router, prefix="/api/v1")
app.include_router(msg_route.router, prefix="/api/v1")
app.include_router(audio_route.router, prefix="/api/v1")
app.include_router(health.router)
app.include_router(scalar_docs.router)

from routes import accounts
app.include_router(accounts.router, prefix="/api/v1")

@app.middleware("http")
async def private_account_responses(request, call_next):
    if not request.url.path.startswith("/api/v1/account"):
        return await call_next(request)
    from pymongo.errors import PyMongoError
    from fastapi.responses import JSONResponse
    try:
        response = await call_next(request)
    except PyMongoError:
        response = JSONResponse(status_code=503, content={"detail": "Account storage is unavailable. Please try again later."})
    response.headers["Cache-Control"] = "private, no-store"
    return response

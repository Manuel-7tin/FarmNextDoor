from fastapi import FastAPI
from dotenv import load_dotenv
from fastapi.middleware.cors import CORSMiddleware
load_dotenv()
from app.config import get_settings
from app.routers import auth, users
# from .config import get_settings
# from .routers import auth, users


settings = get_settings()


app = FastAPI(
    title=settings.app_name,
    version="1.0.0",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.frontend_urls,
    allow_credentials=True,
    allow_methods=[
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ],
    allow_headers=[
        "Content-Type",
        "Accept",
        "X-CSRF-Token",
    ],
)


app.include_router(
    auth.router
)

app.include_router(
    users.router
)


@app.get(
    "/health",
    tags=["Health"],
)
def health():
    return {
        "status": "ok"
    }

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True,
    )

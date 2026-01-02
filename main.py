# main.py
from fastapi import FastAPI
from auth.routes import router
from auth.db import init_db

app = FastAPI(title="Модуль авторизации")

@app.on_event("startup")
async def startup_event():
    await init_db()

app.include_router(router)

@app.get("/")
async def root():
    return {"message": "Модуль авторизации работает. См. /docs"}
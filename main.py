# main.py
from fastapi import FastAPI
from auth.routes import router

app = FastAPI(title="Модуль авторизации")

app.include_router(router)

@app.get("/")
async def root():
    return {"message": "Модуль авторизации работает. См. /docs"}
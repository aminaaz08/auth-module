# auth/db.py
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DB_NAME = os.getenv("DB_NAME")

print(f"🔧 Подключаюсь к MongoDB: {MONGODB_URL}")  # ← ЭТА СТРОКА

if not MONGODB_URL or not DB_NAME:
    raise ValueError("Переменные MONGODB_URL и DB_NAME обязательны!")

client = AsyncIOMotorClient(MONGODB_URL)
database = client[DB_NAME]
users_collection = database.get_collection("users")
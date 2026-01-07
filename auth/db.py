# auth/db.py
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

MONGODB_URL = os.getenv("MONGODB_URL")
DB_NAME = os.getenv("DB_NAME")

if not MONGODB_URL or not DB_NAME:
    raise ValueError("Переменные MONGODB_URL и DB_NAME обязательны!")

client = AsyncIOMotorClient(MONGODB_URL)
database = client[DB_NAME]

# Основные коллекции
users_collection = database.get_collection("users")
codes_collection = database.get_collection("verification_codes")
sessions_collection = database.get_collection("auth_sessions")  # Новая коллекция для сессий

# Создаём TTL-индексы для автоматического удаления
async def init_db():
    # Для кодов верификации (уже было)
    await codes_collection.create_index("created_at", expireAfterSeconds=300)
    
    # Для сессий авторизации (новое)
    # MongoDB автоматически удалит документы, где expires_at < текущее время
    await sessions_collection.create_index("expires_at", expireAfterSeconds=0)
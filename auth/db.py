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

# Создаём TTL-индекс для автоматического удаления кодов через 5 минут
async def init_db():
    await codes_collection.create_index("created_at", expireAfterSeconds=300)
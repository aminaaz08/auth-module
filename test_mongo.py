# test_mongo.py
from motor.motor_asyncio import AsyncIOMotorClient
import asyncio
from dotenv import load_dotenv
import os

load_dotenv()

async def test():
    client = AsyncIOMotorClient(os.getenv("MONGODB_URL"))
    db = client[os.getenv("DB_NAME")]
    try:
        await db.command("ping")
        print("✅ MongoDB подключена!")
        print("Список коллекций:", await db.list_collection_names())
    except Exception as e:
        print("❌ Ошибка подключения:", e)

asyncio.run(test())
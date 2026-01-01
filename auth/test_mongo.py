# test_mongo.py
import asyncio
from motor.motor_asyncio import AsyncIOMotorClient
from dotenv import load_dotenv
import os

load_dotenv()

async def test():
    try:
        print("Подключаюсь к MongoDB...")
        client = AsyncIOMotorClient(os.getenv("MONGODB_URL"))
        db = client[os.getenv("DB_NAME")]
        await db.command("ping")
        print("✅ Успешно! MongoDB отвечает.")
    except Exception as e:
        print("❌ Ошибка:", e)

asyncio.run(test())
# auth/routes.py
from fastapi import APIRouter, HTTPException, status
from auth.models import UserCreate, CodeVerifyRequest  # ← добавлен импорт CodeVerifyRequest
from auth.db import users_collection
from datetime import datetime, timedelta
from jose import jwt
from dotenv import load_dotenv
import secrets
import asyncio
import os

# Загружаем переменные окружения
load_dotenv()

router = APIRouter()

# Временное хранилище кодов (в памяти — только для демо)
verification_codes = {}


async def clear_code_after_delay(email: str, delay: int):
    """Удаляет код через заданное время (в секундах)"""
    await asyncio.sleep(delay)
    verification_codes.pop(email, None)


def create_access_token(data: dict):
    """Создаёт JWT-токен"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1440)))
    to_encode.update({"exp": expire})
    return jwt.encode(
        to_encode,
        os.getenv("SECRET_KEY", "my_super_secret_key_for_jwt_123"),
        algorithm=os.getenv("ALGORITHM", "HS256")
    )


@router.post("/auth/code/request", summary="Запросить одноразовый код")
async def request_code(user: UserCreate):
    """Генерирует и сохраняет 6-значный код для email"""
    email = user.email
    code = secrets.randbelow(1000000)
    code_str = f"{code:06d}"  # всегда 6 цифр

    verification_codes[email] = code_str
    asyncio.create_task(clear_code_after_delay(email, 300))  # удаляется через 5 минут

    # В реальном проекте: отправка через email или Telegram
    print(f"🔐 Код для {email}: {code_str}")

    return {"message": "Код отправлен на email (смотри консоль)"}


@router.post("/auth/code/verify", summary="Подтвердить код и получить токен")
async def verify_code(request: CodeVerifyRequest):
    """Проверяет код и выдаёт JWT-токен"""
    email = request.email
    code = request.code
    expected_code = verification_codes.get(email)

    if not expected_code or expected_code != code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный или просроченный код"
        )

    # Формируем уникальный идентификатор
    external_id = f"email:{email}"

    # Ищем пользователя в MongoDB
    user_in_db = await users_collection.find_one({"external_id": external_id})

    if not user_in_db:
        # Создаём нового пользователя
        new_user = {
            "email": email,
            "auth_method": "code",
            "external_id": external_id,
            "created_at": datetime.utcnow()
        }
        result = await users_collection.insert_one(new_user)
        user_id = str(result.inserted_id)
    else:
        user_id = str(user_in_db["_id"])

    # Генерируем JWT
    access_token = create_access_token(data={"sub": user_id})

    return {"access_token": access_token, "token_type": "bearer"}
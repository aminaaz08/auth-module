# auth/routes.py
from fastapi import APIRouter, HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.models import UserCreate, CodeVerifyRequest
from auth.db import users_collection, codes_collection
from datetime import datetime, timedelta
from jose import jwt, JWTError
from dotenv import load_dotenv
import secrets
import os
from bson import ObjectId

# Загружаем переменные окружения
load_dotenv()

router = APIRouter()

# Настройка Bearer-авторизации
security = HTTPBearer()


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


async def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """
    Извлекает user_id из JWT-токена.
    Вызывает 401 ошибку, если токен недействителен.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(
            token,
            os.getenv("SECRET_KEY"),
            algorithms=[os.getenv("ALGORITHM")]
        )
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный токен"
            )
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Токен недействителен или просрочен"
        )
    return user_id


@router.post("/auth/code/request", summary="Запросить одноразовый код")
async def request_code(user: UserCreate):
    """Генерирует и сохраняет 6-значный код для email в MongoDB"""
    email = user.email
    code = secrets.randbelow(1000000)
    code_str = f"{code:06d}"  # всегда 6 цифр

    # Сохраняем код в MongoDB с отметкой времени
    await codes_collection.insert_one({
        "email": email,
        "code": code_str,
        "created_at": datetime.utcnow()
    })

    # В реальном проекте: отправка через email или Telegram
    print(f"Код для {email}: {code_str}")

    return {"message": "Код отправлен на email (смотри консоль)"}


@router.post("/auth/code/verify", summary="Подтвердить код и получить токен")
async def verify_code(request: CodeVerifyRequest):
    """Проверяет код из MongoDB и выдаёт JWT-токен"""
    email = request.email
    code = request.code

    # Ищем код в MongoDB
    stored_code = await codes_collection.find_one({"email": email, "code": code})

    if not stored_code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный или просроченный код"
        )

    # Удаляем использованный код (повышает безопасность)
    await codes_collection.delete_one({"_id": stored_code["_id"]})

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


@router.get("/me", summary="Получить данные текущего пользователя")
async def get_current_user(user_id: str = Depends(get_current_user_id)):
    """
    Возвращает данные пользователя по токену.
    """
    if not ObjectId.is_valid(user_id):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Неверный формат ID пользователя"
        )

    user = await users_collection.find_one({"_id": ObjectId(user_id)})
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Пользователь не найден"
        )

    return {
        "id": str(user["_id"]),
        "email": user["email"],
        "auth_method": user["auth_method"],
        "external_id": user["external_id"]
    }
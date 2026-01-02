# auth/routes.py
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.models import UserCreate, CodeVerifyRequest
from auth.db import users_collection, codes_collection
from datetime import datetime, timedelta
from jose import jwt, JWTError
from dotenv import load_dotenv
import secrets
import os
import httpx
from bson import ObjectId

# Загружаем переменные окружения
load_dotenv()

router = APIRouter()

# Настройка Bearer-авторизации
security = HTTPBearer()

# GitHub OAuth настройки
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")

# Яндекс OAuth настройки
YANDEX_CLIENT_ID = os.getenv("YANDEX_CLIENT_ID")
YANDEX_CLIENT_SECRET = os.getenv("YANDEX_CLIENT_SECRET")

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


# === GitHub OAuth ===

@router.get("/auth/github", summary="Начать вход через GitHub")
async def github_login():
    """Перенаправляет пользователя на GitHub для авторизации"""
    if not GITHUB_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GITHUB_CLIENT_ID не задан в .env"
        )
    
    github_auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri=http://127.0.0.1:8000/auth/github/callback"
        f"&scope=user:email"
    )
    return RedirectResponse(github_auth_url)


@router.get("/auth/github/callback", summary="Обработать ответ от GitHub")
async def github_callback(code: str):
    """
    Обменивает код от GitHub на access token,
    получает профиль пользователя и выдаёт JWT.
    """
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub OAuth не настроен в .env"
        )

    async with httpx.AsyncClient() as client:
        # Шаг 1: обмен кода на access token
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
            },
            headers={"Accept": "application/json"}
        )
        token_data = token_response.json()

        if "error" in token_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=token_data.get("error_description", "Ошибка GitHub")
            )

        access_token = token_data["access_token"]

        # Шаг 2: получение профиля пользователя
        user_response = await client.get(
            "https://api.github.com/user",
            headers={"Authorization": f"token {access_token}"}
        )
        user_data = user_response.json()

        # Шаг 3: получение email (если не в профиле)
        email = user_data.get("email")
        if not email:
            emails_response = await client.get(
                "https://api.github.com/user/emails",
                headers={"Authorization": f"token {access_token}"}
            )
            emails = emails_response.json()
            email = next((e["email"] for e in emails if e["primary"]), None)

        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Не удалось получить email от GitHub"
            )

        # Шаг 4: сохранение/поиск пользователя
        external_id = f"gh_{user_data['id']}"
        user_in_db = await users_collection.find_one({"external_id": external_id})

        if not user_in_db:
            new_user = {
                "email": email,
                "auth_method": "github",
                "external_id": external_id,
                "created_at": datetime.utcnow()
            }
            result = await users_collection.insert_one(new_user)
            user_id = str(result.inserted_id)
        else:
            user_id = str(user_in_db["_id"])

        # Шаг 5: выдача JWT
        jwt_token = create_access_token(data={"sub": user_id})

        # Для демо: показываем токен в Swagger
        return RedirectResponse(
            url=f"http://127.0.0.1:8000/docs?token={jwt_token}"
        )
    
# === ЯндексID OAuth ===

@router.get("/auth/yandex", summary="Начать вход через ЯндексID")
async def yandex_login():
    """Перенаправляет пользователя на Яндекс для авторизации"""
    if not YANDEX_CLIENT_ID:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="YANDEX_CLIENT_ID не задан в .env"
        )
    
    yandex_auth_url = (
        f"https://oauth.yandex.ru/authorize"
        f"?response_type=code"
        f"&client_id={YANDEX_CLIENT_ID}"
        f"&redirect_uri=http://127.0.0.1:8000/docs/auth/yandex/callback"
    )
    return RedirectResponse(yandex_auth_url)


@router.get("/auth/yandex/callback", summary="Обработать ответ от ЯндексID")
async def yandex_callback(code: str):
    """
    Обменивает код от Яндекса на access token,
    получает профиль пользователя и выдаёт JWT.
    """
    if not YANDEX_CLIENT_ID or not YANDEX_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Яндекс OAuth не настроен в .env"
        )

    async with httpx.AsyncClient() as client:
        # Шаг 1: обмен кода на access token
        token_response = await client.post(
            "https://oauth.yandex.ru/token",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "client_id": YANDEX_CLIENT_ID,
                "client_secret": YANDEX_CLIENT_SECRET,
            }
        )
        token_data = token_response.json()

        if "error" in token_data:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=token_data.get("error_description", "Ошибка Яндекса")
            )

        access_token = token_data["access_token"]

        # Шаг 2: получение профиля пользователя
        user_response = await client.get(
            "https://login.yandex.ru/info?format=json",
            headers={"Authorization": f"OAuth {access_token}"}
        )
        user_data = user_response.json()

        # Шаг 3: извлечение email и логина
        email = user_data.get("default_email") or user_data.get("login") + "@yandex.ru"
        yandex_id = user_data["id"]

        if not email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Не удалось получить email от Яндекса"
            )

        # Шаг 4: сохранение/поиск пользователя
        external_id = f"ya_{yandex_id}"
        user_in_db = await users_collection.find_one({"external_id": external_id})

        if not user_in_db:
            new_user = {
                "email": email,
                "auth_method": "yandex",
                "external_id": external_id,
                "created_at": datetime.utcnow()
            }
            result = await users_collection.insert_one(new_user)
            user_id = str(result.inserted_id)
        else:
            user_id = str(user_in_db["_id"])

        # Шаг 5: выдача JWT
        jwt_token = create_access_token(data={"sub": user_id})

        # Для демо: показываем токен в Swagger
        return RedirectResponse(
            url=f"http://127.0.0.1:8000//docs?token={jwt_token}"
        )
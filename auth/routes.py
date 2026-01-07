# auth/routes.py
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.models import UserCreate, CodeVerifyRequest, AuthInitRequest
from auth.db import users_collection, codes_collection, sessions_collection
from datetime import datetime, timedelta
from jose import jwt, JWTError
from dotenv import load_dotenv
import secrets
import os
import httpx
from bson import ObjectId
import random

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

# Конфигурация токенов
SECRET_KEY = os.getenv("SECRET_KEY", "my_super_secret_key_for_jwt_123")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 1440))
REFRESH_TOKEN_EXPIRE_DAYS = 7


def create_access_token(data: dict):
    """Создаёт JWT-токен доступа"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "type": "access"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token(data: dict):
    """Создаёт JWT-токен обновления"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user_id(
    credentials: HTTPAuthorizationCredentials = Depends(security)
) -> str:
    """
    Извлекает user_id из JWT-токена.
    Вызывает 401 ошибку, если токен недействителен.
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        token_type = payload.get("type")
        if token_type != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Требуется токен доступа"
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


# === Инициализация авторизации ===

@router.post("/auth/init", summary="Инициировать авторизацию через провайдера")
async def init_auth(request: AuthInitRequest):
    """
    Инициирует авторизацию через GitHub или Яндекс.
    Принимает entry_token от клиента и возвращает ссылку для перехода.
    """
    # Проверяем, что провайдер поддерживается
    if request.provider not in ["github", "yandex"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неподдерживаемый провайдер"
        )
    
    # Генерируем expires_at (текущее время + 5 минут)
    expires_at = datetime.utcnow() + timedelta(minutes=5)
    
    # Сохраняем сессию в MongoDB
    session_data = {
        "entry_token": request.entry_token,
        "provider": request.provider,
        "expires_at": expires_at,
        "status": "pending",
        "created_at": datetime.utcnow()
    }
    await sessions_collection.insert_one(session_data)
    
    # Формируем ссылку в зависимости от провайдера
    if request.provider == "github":
        auth_url = (
            f"https://github.com/login/oauth/authorize"
            f"?client_id={GITHUB_CLIENT_ID}"
            f"&redirect_uri=http://127.0.0.1:8000/auth/github/callback"
            f"&state={request.entry_token}"  # КЛЮЧЕВОЙ ПАРАМЕТР
            f"&scope=user:email"
        )
    else:  # yandex
        auth_url = (
            f"https://oauth.yandex.ru/authorize"
            f"?response_type=code"
            f"&client_id={YANDEX_CLIENT_ID}"
            f"&redirect_uri=http://127.0.0.1:8000/auth/yandex/callback"
            f"&state={request.entry_token}"  # КЛЮЧЕВОЙ ПАРАМЕТР
        )
    
    return {
        "auth_url": auth_url,
        "expires_in": 300  # 5 минут в секундах
    }

# === Обновление токена ===
@router.post("/auth/refresh", summary="Обновить access token")
async def refresh_token(refresh_token_str: str):
    """
    Обновляет access token с использованием refresh token
    """
    try:
        payload = jwt.decode(refresh_token_str, SECRET_KEY, algorithms=[ALGORITHM])
        token_type = payload.get("type")
        if token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Требуется refresh token"
            )
        
        user_id = payload.get("sub")
        email = payload.get("email")
        if not user_id or not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный refresh token"
            )
        
        # Проверяем, что refresh token есть в базе
        user = await users_collection.find_one({
            "_id": ObjectId(user_id),
            "refresh_tokens": refresh_token_str
        })
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token недействителен"
            )
        
        # Генерируем новые токены
        new_access_token = create_access_token(data={"sub": user_id})
        new_refresh_token = create_refresh_token(data={"sub": user_id, "email": email})
        
        # Обновляем refresh token в базе (два отдельных запроса!)
        await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$pull": {"refresh_tokens": refresh_token_str}}
        )
        await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$addToSet": {"refresh_tokens": new_refresh_token}}
        )
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token недействителен или просрочен"
        )

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
        # Создаём нового пользователя с именем "Аноним+номер"
        last_anon = await users_collection.find_one(
            {"name": {"$regex": "^Аноним"}},
            sort=[("anon_id", -1)]
        )
        next_id = (last_anon["anon_id"] + 1) if last_anon else 1
        
        new_user = {
            "name": f"Аноним{next_id}",
            "email": email,
            "auth_method": "code",
            "external_id": external_id,
            "roles": ["Студент"],
            "refresh_tokens": [],
            "anon_id": next_id,
            "created_at": datetime.utcnow()
        }
        result = await users_collection.insert_one(new_user)
        user_id = str(result.inserted_id)
    else:
        user_id = str(user_in_db["_id"])

    # Генерируем JWT токены
    access_token = create_access_token(data={"sub": user_id})
    refresh_token = create_refresh_token(data={"sub": user_id, "email": email})
    
    # Сохраняем refresh token в базу
    await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$addToSet": {"refresh_tokens": refresh_token}}
    )

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }


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
        "name": user.get("name", user["email"].split("@")[0]),
        "email": user["email"],
        "roles": user.get("roles", ["Студент"]),
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
async def github_callback(code: str = None, state: str = None, error: str = None):
    """
    Обменивает код от GitHub на access token,
    получает профиль пользователя и выдаёт JWT.
    """
    # Обработка ошибки от провайдера
    if error == "access_denied":
        if state:
            await sessions_collection.update_one(
                {"entry_token": state, "provider": "github"},
                {"$set": {"status": "denied"}}
            )
        return HTMLResponse(f"""
        <html>
            <body style="text-align: center; padding: 50px; font-family: Arial, sans-serif; background-color: #f8f9fa;">
                <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h1 style="color: #dc3545;">❌ Доступ запрещён</h1>
                    <p style="font-size: 1.1em; margin: 20px 0;">Пользователь отказался от авторизации</p>
                    <p>Вернитесь в приложение для повторной попытки.</p>
                    <small style="color: #6c757d; margin-top: 20px; display: block;">Сессия: {state or 'не указана'}</small>
                </div>
            </body>
        </html>
        """)
    
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Отсутствует код авторизации"
        )
    
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="GitHub OAuth не настроен в .env"
        )

    # Если есть state, ищем сессию
    session = None
    if state:
        session = await sessions_collection.find_one({
            "entry_token": state,
            "provider": "github",
            "status": "pending",
            "expires_at": {"$gt": datetime.utcnow()}
        })
        if not session:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Неверный или просроченный state"
            )
    
    async with httpx.AsyncClient() as client:
        # Шаг 1: обмен кода на access token
        token_response = await client.post(
            "https://github.com/login/oauth/access_token",
            data={
                "client_id": GITHUB_CLIENT_ID,
                "client_secret": GITHUB_CLIENT_SECRET,
                "code": code,
                "state": state  # GitHub требует передачи state здесь тоже!
            },
            headers={"Accept": "application/json"}
        )
        token_data = token_response.json()

        if "error" in token_data:
            # Обновляем статус сессии, если есть
            if session:
                await sessions_collection.update_one(
                    {"_id": session["_id"]},
                    {"$set": {"status": "denied"}}
                )
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
            # Генерация имени "Аноним+номер" и роли "Студент"
            last_anon = await users_collection.find_one(
                {"name": {"$regex": "^Аноним"}},
                sort=[("anon_id", -1)]
            )
            next_id = (last_anon["anon_id"] + 1) if last_anon else 1
            
            new_user = {
                "name": f"Аноним{next_id}",
                "email": email,
                "auth_method": "github",
                "external_id": external_id,
                "roles": ["Студент"],
                "refresh_tokens": [],
                "anon_id": next_id,
                "created_at": datetime.utcnow()
            }
            result = await users_collection.insert_one(new_user)
            user_id = str(result.inserted_id)
        else:
            user_id = str(user_in_db["_id"])

        # Шаг 5: выдача JWT токенов
        access_token_jwt = create_access_token(data={"sub": user_id})
        refresh_token_jwt = create_refresh_token(data={"sub": user_id, "email": email})
        
        # Сохраняем refresh token в базу
        await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$addToSet": {"refresh_tokens": refresh_token_jwt}}
        )

        # Обновляем сессию, если есть
        if session:
            await sessions_collection.update_one(
                {"_id": session["_id"]},
                {
                    "$set": {
                        "status": "granted",
                        "access_token": access_token_jwt,
                        "refresh_token": refresh_token_jwt,
                        "user_email": email
                    }
                }
            )

        # Возвращаем HTML страницу для клиента
        if session:
            return HTMLResponse(f"""
            <html>
                <body style="text-align: center; padding: 50px; font-family: Arial, sans-serif; background-color: #f8f9fa;">
                    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <h1 style="color: #28a745;">✅ Авторизация успешна!</h1>
                        <p style="font-size: 1.1em; margin: 20px 0;">Вы успешно вошли через GitHub</p>
                        <p>Вернитесь в приложение для продолжения.</p>
                        <div style="background: #e9ecef; padding: 15px; border-radius: 5px; margin-top: 20px; font-family: monospace; font-size: 0.9em;">
                            Сессия: {state}
                        </div>
                    </div>
                </body>
            </html>
            """)
        else:
            # Старое поведение для прямого вызова
            return RedirectResponse(
                url=f"http://127.0.0.1:8000/docs?token={access_token_jwt}"
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
        f"&redirect_uri=http://127.0.0.1:8000/auth/yandex/callback"
    )
    return RedirectResponse(yandex_auth_url)


@router.get("/auth/yandex/callback", summary="Обработать ответ от ЯндексID")
async def yandex_callback(code: str = None, state: str = None, error: str = None):
    """
    Обменивает код от Яндекса на access token,
    получает профиль пользователя и выдаёт JWT.
    """
    # Обработка ошибки от провайдера
    if error == "access_denied":
        if state:
            await sessions_collection.update_one(
                {"entry_token": state, "provider": "yandex"},
                {"$set": {"status": "denied"}}
            )
        return HTMLResponse(f"""
        <html>
            <body style="text-align: center; padding: 50px; font-family: Arial, sans-serif; background-color: #f8f9fa;">
                <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                    <h1 style="color: #dc3545;">❌ Доступ запрещён</h1>
                    <p style="font-size: 1.1em; margin: 20px 0;">Пользователь отказался от авторизации</p>
                    <p>Вернитесь в приложение для повторной попытки.</p>
                    <small style="color: #6c757d; margin-top: 20px; display: block;">Сессия: {state or 'не указана'}</small>
                </div>
            </body>
        </html>
        """)
    
    if not code:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Отсутствует код авторизации"
        )
    
    if not YANDEX_CLIENT_ID or not YANDEX_CLIENT_SECRET:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Яндекс OAuth не настроен в .env"
        )

    # Если есть state, ищем сессию
    session = None
    if state:
        session = await sessions_collection.find_one({
            "entry_token": state,
            "provider": "yandex",
            "status": "pending",
            "expires_at": {"$gt": datetime.utcnow()}
        })
        if not session:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Неверный или просроченный state"
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
                # Для Яндекса state не передаётся здесь
            }
        )
        token_data = token_response.json()

        if "error" in token_data:
            # Обновляем статус сессии, если есть
            if session:
                await sessions_collection.update_one(
                    {"_id": session["_id"]},
                    {"$set": {"status": "denied"}}
                )
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
            # Генерация имени "Аноним+номер" и роли "Студент"
            last_anon = await users_collection.find_one(
                {"name": {"$regex": "^Аноним"}},
                sort=[("anon_id", -1)]
            )
            next_id = (last_anon["anon_id"] + 1) if last_anon else 1
            
            new_user = {
                "name": f"Аноним{next_id}",
                "email": email,
                "auth_method": "yandex",
                "external_id": external_id,
                "roles": ["Студент"],
                "refresh_tokens": [],
                "anon_id": next_id,
                "created_at": datetime.utcnow()
            }
            result = await users_collection.insert_one(new_user)
            user_id = str(result.inserted_id)
        else:
            user_id = str(user_in_db["_id"])

        # Шаг 5: выдача JWT токенов
        access_token_jwt = create_access_token(data={"sub": user_id})
        refresh_token_jwt = create_refresh_token(data={"sub": user_id, "email": email})
        
        # Сохраняем refresh token в базу
        await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$addToSet": {"refresh_tokens": refresh_token_jwt}}
        )

        # Обновляем сессию, если есть
        if session:
            await sessions_collection.update_one(
                {"_id": session["_id"]},
                {
                    "$set": {
                        "status": "granted",
                        "access_token": access_token_jwt,
                        "refresh_token": refresh_token_jwt,
                        "user_email": email
                    }
                }
            )

        # Возвращаем HTML страницу для клиента
        if session:
            return HTMLResponse(f"""
            <html>
                <body style="text-align: center; padding: 50px; font-family: Arial, sans-serif; background-color: #f8f9fa;">
                    <div style="max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1);">
                        <h1 style="color: #28a745;">✅ Авторизация успешна!</h1>
                        <p style="font-size: 1.1em; margin: 20px 0;">Вы успешно вошли через ЯндексID</p>
                        <p>Вернитесь в приложение для продолжения.</p>
                        <div style="background: #e9ecef; padding: 15px; border-radius: 5px; margin-top: 20px; font-family: monospace; font-size: 0.9em;">
                            Сессия: {state}
                        </div>
                    </div>
                </body>
            </html>
            """)
        else:
            # Старое поведение для прямого вызова
            return RedirectResponse(
                url=f"http://127.0.0.1:8000/docs?token={access_token_jwt}"
            )


# === Обновление токена ===
@router.post("/auth/refresh", summary="Обновить access token")
async def refresh_token(refresh_token: str):
    """
    Обновляет access token с использованием refresh token
    """
    try:
        payload = jwt.decode(refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        token_type = payload.get("type")
        if token_type != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Требуется refresh token"
            )
        
        user_id = payload.get("sub")
        email = payload.get("email")
        if not user_id or not email:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Неверный refresh token"
            )
        
        # Проверяем, что refresh token есть в базе
        user = await users_collection.find_one({
            "_id": ObjectId(user_id),
            "refresh_tokens": refresh_token
        })
        
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Refresh token недействителен"
            )
        
        # Генерируем новые токены
        new_access_token = create_access_token(data={"sub": user_id})
        new_refresh_token = create_refresh_token(data={"sub": user_id, "email": email})
        
        # Обновляем refresh token в базе
        await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$pull": {"refresh_tokens": refresh_token},
                "$addToSet": {"refresh_tokens": new_refresh_token}
            }
        )
        
        return {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "token_type": "bearer"
        }
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token недействителен или просрочен"
        )
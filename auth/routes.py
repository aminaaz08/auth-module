# auth/routes.py
from fastapi import APIRouter, HTTPException, status, Depends, Request
from fastapi.responses import RedirectResponse, HTMLResponse, JSONResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from auth.models import UserCreate, CodeVerifyRequest, AuthInitRequest, CodeSubmitRequest
from auth.db import users_collection, codes_collection, sessions_collection, code_sessions_collection
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
    Инициирует авторизацию через GitHub, Яндекс или код.
    Принимает entry_token от клиента и возвращает ссылку или код.
    Поддерживает передачу ролей: ["Студент"], ["Преподаватель"], ["Админ"] (массив).
    Если роли не указаны — используется ["Студент"] по умолчанию.
    """
    # Определяем роли: если не переданы — Студент по умолчанию
    roles = request.roles or ["Студент"]
    
    if request.provider == "code":
        # Генерация 6-значного кода
        code = f"{secrets.randbelow(1000000):06d}"
        
        # Сохраняем: код → { entry_token, expires_at }
        await code_sessions_collection.insert_one({
            "code": code,
            "entry_token": request.entry_token,
            "expires_at": datetime.utcnow() + timedelta(minutes=1),
            "created_at": datetime.utcnow()
        })
        
        # Создаём сессию авторизации (на 5 минут) — сохраняем роли
        await sessions_collection.insert_one({
            "entry_token": request.entry_token,
            "provider": "code",
            "expires_at": datetime.utcnow() + timedelta(minutes=5),
            "status": "pending",
            "roles": roles 
        })
        
        # 💡 Возвращаем КОД (не URL!)
        return {
            "code": code,
            "expires_in": 60  # секунд
        }
    
    elif request.provider in ["github", "yandex"]:
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
            "created_at": datetime.utcnow(),
            "roles": roles  
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
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неподдерживаемый провайдер"
        )
    
@router.post("/auth/code/request", summary="Запросить одноразовый код")
async def request_code(user: UserCreate):
    """Генерирует и сохраняет 6-значный код для email в MongoDB"""
    email = user.email
    code = secrets.randbelow(1000000)
    code_str = f"{code:06d}"  # всегда 6 цифр

    # Отладочный вывод: начало операции
    print(f"⏳ Пытаюсь сохранить код в MongoDB для {email}...")

    try:
        # Сохраняем код в MongoDB с отметкой времени
        result = await codes_collection.insert_one({
            "email": email,
            "code": code_str,
            "created_at": datetime.utcnow()
        })
        # Отладочный вывод: успех
        print(f"✅ Код успешно сохранён в MongoDB! ID документа: {result.inserted_id}")
        print(f"🔐 Код для {email}: {code_str}")  # Код теперь точно виден

    except Exception as e:
        # Отладочный вывод: ошибка
        print(f"❌ ОШИБКА при сохранении в MongoDB: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Не удалось сохранить код в базу данных"
        )

    # ОБЯЗАТЕЛЬНЫЙ RETURN — иначе будет null
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
        # ИСПОЛЬЗУЕМ РОЛИ ИЗ ЗАПРОСА
        roles = request.roles or ["Студент"]
        
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
            "roles": roles,  
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

# === Подтверждение кода с другого устройства ===

@router.post("/auth/code/submit", summary="Подтвердить код с другого устройства")
async def submit_code(request: CodeSubmitRequest):
    """
    Проверяет код и refresh_token, затем завершает авторизацию.
    """
    # Шаг 1: ищем код в code_sessions_collection
    code_session = await code_sessions_collection.find_one({
        "code": request.code,
        "expires_at": {"$gt": datetime.utcnow()}
    })
    
    if not code_session:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Неверный или просроченный код"
        )
    
    entry_token = code_session["entry_token"]
    
    # Шаг 2: ищем сессию, чтобы получить роли
    session = await sessions_collection.find_one({
        "entry_token": entry_token,
        "status": "pending"
    })
    
    # Шаг 3: проверяем refresh_token
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "refresh":
            raise JWTError("Неверный тип токена")
        email = payload.get("email")
        if not email:
            raise JWTError("Email отсутствует в токене")
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Недействительный refresh token: {str(e)}"
        )
    
    # Шаг 4: удаляем использованный код
    await code_sessions_collection.delete_one({"_id": code_session["_id"]})
    
    # Шаг 5: теперь — общий флоу (как в GitHub/Yandex)
    # Ищем или создаём пользователя
    external_id = f"email:{email}"
    user_in_db = await users_collection.find_one({"external_id": external_id})
    
    if not user_in_db:
        # Получаем роли из сессии (или Студент по умолчанию)
        roles = session.get("roles", ["Студент"]) if session else ["Студент"]
        
        # Генерация "Аноним+номер"
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
            "roles": roles,  
            "refresh_tokens": [request.refresh_token],
            "anon_id": next_id,
            "created_at": datetime.utcnow()
        }
        result = await users_collection.insert_one(new_user)
        user_id = str(result.inserted_id)
    else:
        user_id = str(user_in_db["_id"])
        # Обновляем refresh_tokens (если нужно)
        await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {"$addToSet": {"refresh_tokens": request.refresh_token}}
        )
    
    # Шаг 6: генерируем новые токены
    access_token = create_access_token(data={"sub": user_id})
    refresh_token_new = create_refresh_token(data={"sub": user_id, "email": email})
    
    # Обновляем refresh_tokens в базе
    await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$pull": {"refresh_tokens": request.refresh_token}}
    )
    await users_collection.update_one(
        {"_id": ObjectId(user_id)},
        {"$addToSet": {"refresh_tokens": refresh_token_new}}
    )
    
    # Шаг 7: обновляем сессию авторизации
    await sessions_collection.update_one(
        {"entry_token": entry_token},
        {
            "$set": {
                "status": "granted",
                "access_token": access_token,
                "refresh_token": refresh_token_new,
                "user_email": email
            }
        }
    )
    
    return {"status": "success", "message": "Авторизация завершена"}


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
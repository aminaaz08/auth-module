# Модуль авторизации — инструкция для интеграции

Этот модуль предоставляет API для аутентификации пользователей через:
- одноразовый код (на email),
- GitHub OAuth,
- ЯндексID.

Все данные хранятся в MongoDB, выдаётся JWT-токен, который можно использовать для доступа к другим частям системы.

---

## Как запустить локально

### 1. Требования
- Python 3.9+
- MongoDB (локально или Atlas)
- Виртуальное окружение (рекомендуется)

### 2. Установка
#### Клонируйте репозиторий (если ещё не сделано)
```
git clone <https://github.com/aminaaz08/auth-module>
cd auth-module
```
#### Создайте виртуальное окружение
```
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
```
#### Установите зависимости
```
pip install -r requirements.txt
```
### 3. Настройка
файл .env в корне проекта:

.env
```
# Обязательные переменные
MONGODB_URL=mongodb://localhost:27017
DB_NAME=auth_dbSECRET_KEY=ваш_надёжный_секретный_ключ_длиной_минимум_32_символа
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Для GitHub OAuth (опционально)
GITHUB_CLIENT_ID=ваш_client_id
GITHUB_CLIENT_SECRET=ваш_client_secret

# Для ЯндексID (опционально)
YANDEX_CLIENT_ID=ваш_yandex_client_id
YANDEX_CLIENT_SECRET=ваш_yandex_client_secret
```
Совет: для генерации SECRET_KEY можно использовать:
```
import secrets
print(secrets.token_hex(32))
```

### 4. Запуск
bash
```
uvicorn main:app --reload
```
Сервер будет доступен по адресу:
http://localhost:8000

Документация API:
http://localhost:8000/docs

### Доступные эндпоинты

#### * Авторизация по коду
Запросить код
POST /auth/code/request
Тело: {"email": "user@example.com"}
→ Код появится в консоли сервера (в реальном проекте — отправляется на email/Telegram).
Подтвердить код
POST /auth/code/verify
Тело: {"email": "user@example.com", "code": "123456"}
→ В ответе: {"access_token": "...", "token_type": "bearer"}

#### * Авторизация через GitHub
Перейдите в браузере по ссылке:
http://localhost:8000/auth/github
После входа вы получите JWT-токен в URL (для демо).

#### * Авторизация через ЯндексID
Перейдите в браузере по ссылке:
http://localhost:8000/auth/yandex
После входа вы получите JWT-токен в URL (для демо).

#### * Получение данных пользователя
GET /me
Требует заголовок: Authorization: Bearer <ваш_токен>
→ Возвращает:

json
```
{
    "id": "65a...",  
    "email": "user@example.com",  
    "auth_method": "code", // или "github", "yandex"
    "external_id": "email:user@example.com" // или "gh_12345"
}
```
#### *  Как интегрироваться
#### Для Web-клиента
- При входе вызывайте нужный метод:
/auth/code/request → /auth/code/verify (по коду),
/auth/github (GitHub),
/auth/yandex (ЯндексID).
- Сохраняйте полученный access_token.
- При запросах к другим сервисам передавайте заголовок:
http
````
Authorization: Bearer eyJhbGciOi...
````
- Чтобы получить данные пользователя — вызывайте GET /me.
 
#### Для Telegram-бота
- Бот может вызывать /auth/code/request с email пользователя.
- Код можно отправить в Telegram (в будущем — автоматизируем).
- После получения кода от пользователя — вызвать /auth/code/verify.

#### Для модуля тестов
- Используйте user.id из /me для привязки результатов тестов к пользователю.
- Храните external_id, если нужно различать источники (email, GitHub, Яндекс).

#### *  Структура проекта
```
auth-module/
├── main.py              # точка входа
├── .env                 # переменные окружения (не коммитить!)
├── requirements.txt     # зависимости
└── auth/
    ├── db.py            # подключение к MongoDB
    ├── models.py        # Pydantic-модели
    └── routes.py        # все эндпоинты
```

# Модуль авторизации

Реализация аутентификации для платформы массовых опросов и тестирования.  
Поддерживает вход по одноразовому коду, через GitHub и ЯндексID.  
Выдаёт JWT-токен для интеграции с Web, Telegram и другими модулями.

---

## Возможности

-  Авторизация по одноразовому коду (email)
-  Вход через **GitHub OAuth**
-  Вход через **ЯндексID**
-  Хранение пользователей в **MongoDB**
-  Выдача **JWT-токенов** с 24-часовым сроком действия
-  Эндпоинт `/me` для проверки токена и получения данных пользователя
-  Автоматическая очистка кодов через 5 минут (TTL-индекс в MongoDB)

---

## Быстрый старт

#### Требования
- Python 3.9+
- MongoDB (локально или Atlas)

#### Установка
```bash
# Клонируйте репозиторий
git clone https://github.com/aminaaz08/auth-module.git
cd auth-module
```
#### Виртуальное окружение
```
python -m venv venv
source venv/bin/activate      # Linux/Mac
venv\Scripts\activate         # Windows
```
#### Зависимости
```
pip install -r requirements.txt
```
#### Настройка
Создайте .env в корне проекта:
```
MONGODB_URL=mongodb://localhost:27017
DB_NAME=auth_db
SECRET_KEY=ваш_секретный_ключ_32+символов
ALGORITHM=HS256
ACCESS_TOKEN_EXPIRE_MINUTES=1440

# Опционально: для OAuth
GITHUB_CLIENT_ID=...
GITHUB_CLIENT_SECRET=...
YANDEX_CLIENT_ID=...
YANDEX_CLIENT_SECRET=...
```
#### Запуск 
```
uvicorn main:app --reload
```
> API будет доступно по адресу: http://localhost:8000

> Документация: http://localhost:8000/docs
#### Основные эндпоинты
|     Метод     |      Эндпоинт       |                   Описание                   |
| ------------- | ------------------- | -------------------------------------------- |
| POST          | /auth/code/request  | Запросить код на email                       |
| POST          | /auth/code/verify   | Подтвердить код и получить токен             |
| GET           | /auth/github        | Начать вход через GitHub                     |
| GET           | /auth/yandex        | Начать вход через ЯндексID                   |
| GET           | /me                 | Получить данные пользователя (требует токен) |

> Полная документация доступна в интерфейсе Swagger: http://localhost:8000/docs
#### Интеграция
- Web-клиент: вызывайте нужный метод авторизации → сохраняйте JWT → отправляйте в заголовке Authorization: Bearer <токен>.
- Telegram-бот: может запрашивать код и проверять его через API.
- Модуль тестов: используйте id из /me для привязки результатов.

Подробная инструкция: `AUTH_INTEGRATION.md`

#### Структура проекта
```
auth-module/
├── main.py              # Точка входа
├── .env                 # Файл настроек
├── requirements.txt     # Зависимости
├── AUTH_INTEGRATION.md  # Инструкция для команды
└── auth/                # Логика модуля
    ├── _init__.py       # Пустой фойл для импортирования модулей из этой папки
    ├── db.py            # Подключение к MongoDB
    ├── models.py        # Pydantic-модели
    ├── routes.py        # Эндпоинты
    └── utils.py         # Общие вспомогательные утилиты и зависимости
```

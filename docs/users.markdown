# Документация для модуля `users.py`

## Описание
`users.py` содержит класс `UserManager`, который управляет пользователями и сессиями в TunderOS. Он отвечает за аутентификацию, создание, удаление и изменение паролей пользователей, а также управление сессиями.

## Зависимости
- Python 3.8+
- Модули Python: `sqlite3`, `time`, `pathlib`, `os`, `sys`, `cryptography.hazmat.primitives`
- Внутренние модули:
  - `libs.logging.Logger`
  - `libs.CrashHandler.CrashHandler`
  - `TNFS.TNFS`

## Класс `UserManager`

### `__init__(self, logger: Logger, crash_handler: CrashHandler)`
- **Описание**: Инициализирует менеджер пользователей.
- **Параметры**:
  - `logger`: Экземпляр `Logger` для логирования.
  - `crash_handler`: Экземпляр `CrashHandler` для обработки ошибок.
- **Действия**:
  - Создает SQLite базу данных `data/users.db`.
  - Создает таблицы `users` (username, password, role) и `sessions` (session_id, username, login_time).
  - Вызывает `init_default_users` для создания пользователей по умолчанию.
  - Устанавливает `current_session_id` в `None`.

### `init_default_users(self)`
- **Описание**: Создает пользователей по умолчанию (`root`, `guest`, `user`) с соответствующими паролями и ролями.
- **Действия**:
  - Проверяет, существуют ли пользователи в базе данных.
  - Добавляет их, если они отсутствуют.
  - Сохраняет изменения в базе данных.

### `login(self, username: str, password: str) -> bool`
- **Описание**: Выполняет вход пользователя.
- **Параметры**:
  - `username`: Имя пользователя.
  - `password`: Пароль.
- **Возвращает**: `True` при успешном входе, иначе вызывает `TunderCrash`.
- **Действия**:
  - Проверяет соответствие пароля в базе данных.
  - Создает новую сессию в таблице `sessions`.
  - Устанавливает `current_session_id`.
  - Обновляет `current_user` и `current_role` в `tnfs`.

### `logout(self, session_id: int) -> bool`
- **Описание**: Выполняет выход из сессии.
- **Параметры**:
  - `session_id`: ID сессии.
- **Возвращает**: `True` при успешном выходе, иначе вызывает `TunderCrash`.
- **Действия**:
  - Проверяет существование сессии.
  - Удаляет сессию из базы данных.
  - Сбрасывает `current_session_id` и `tnfs.current_user/role`, если сессия текущая.

### `add_user(self, username: str, password: str, role: str = "user") -> bool`
- **Описание**: Добавляет нового пользователя.
- **Параметры**:
  - `username`: Имя пользователя.
  - `password`: Пароль.
  - `role`: Роль (по умолчанию `"user"`).
- **Возвращает**: `True` при успехе, иначе вызывает `TunderCrash`.
- **Действия**:
  - Проверяет, существует ли пользователь.
  - Добавляет нового пользователя в базу данных.

### `delete_user(self, username: str) -> bool`
- **Описание**: Удаляет пользователя и его сессии.
- **Параметры**:
  - `username`: Имя пользователя.
- **Возвращает**: `True` при успехе, иначе вызывает `TunderCrash`.

### `change_password(self, username: str, old_password: str, new_password: str) -> bool`
- **Описание**: Изменяет пароль пользователя.
- **Параметры**:
  - `username`: Имя пользователя.
  - `old_password`: Старый пароль.
  - `new_password`: Новый пароль.
- **Возвращает**: `True` при успехе, иначе вызывает `TunderCrash`.

### `start_session(self, username: str) -> int`
- **Описание**: Создает новую сессию для пользователя.
- **Параметры**:
  - `username`: Имя пользователя.
- **Возвращает**: ID новой сессии.
- **Действия**:
  - Проверяет существование пользователя.
  - Создает запись в таблице `sessions` с текущим временем и статусом `"active"`.

### `end_session(self, session_id: int) -> bool`
- **Описание**: Завершает сессию.
- **Параметры**:
  - `session_id`: ID сессии.
- **Возвращает**: `True` при успехе, иначе вызывает `TunderCrash`.
- **Действия**:
  - Проверяет существование и статус сессии.
  - Обновляет статус на `"closed"` и добавляет `logout_time`.

### `get_active_sessions(self) -> List[Dict]`
- **Описание**: Возвращает список активных сессий.
- **Возвращает**: Список словарей с ключами `session_id`, `username`, `login_time`.

### `get_session_info(self, session_id: int) -> Dict`
- **Описание**: Возвращает информацию о сессии.
- **Параметры**:
  - `session_id`: ID сессии.
- **Возвращает**: Словарь с `session_id`, `username`, `login_time`.

### `get_user_info(self, username: str) -> Dict`
- **Описание**: Возвращает информацию о пользователе.
- **Параметры**:
  - `username`: Имя пользователя.
- **Возвращает**: Словарь с `username`, `role`, `home_dir`, `uid`, `created_at`.

## Логирование
- Логи сохраняются в `data/logs/users.log`.
- Примеры логов:
  ```
  {"timestamp": "2025-06-27 23:19:26", "level": "INFO", "name": "users", "message": "UserManager initialized"}
  {"timestamp": "2025-06-27 23:19:27", "level": "INFO", "name": "users", "message": "User root logged in (session 1)"}
  ```

## Замечания
- Пароли хранятся в открытом виде, что является уязвимостью. Рекомендуется использовать шифрование (например, `PBKDF2HMAC` из `cryptography`).
- Метод `end_session` содержит ошибку: обращение к `self.current_user` и `self.skfs` вместо `self.tnfs`.

## Рекомендации
- Исправить `end_session`, заменив `self.current_user` на `self.tnfs.current_user` и `self.skfs` на `self.tnfs`.
- Добавить хеширование паролей:
  ```python
  def hash_password(self, password: str) -> str:
      salt = os.urandom(32)
      kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
      key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
      return f"{base64.urlsafe_b64encode(salt).decode()}:{key.decode()}"
  ```
- Добавить проверку сложности паролей.
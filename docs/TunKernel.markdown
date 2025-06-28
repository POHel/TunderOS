# Документация для модуля `TunKernel.py`

## Описание
`TunKernel.py` содержит класс `Kernel`, который является ядром TunderOS, обеспечивающим взаимодействие между компонентами: файловой системой (`TNFS`), менеджером пользователей (`UserManager`) и SELinux. Ядро предоставляет высокоуровневые методы для операций с файлами, пользователями и сессиями.

## Зависимости
- Python 3.8+
- Модули Python: `pathlib`, `os`, `sys`
- Внутренние модули:
  - `TNFS.TNFS`
  - `core.users.UserManager`
  - `security.SELinux.SELinux`
  - `libs.logging.Logger`
  - `libs.CrashHandler.CrashHandler`

## Класс `Kernel`

### `__init__(self, logger: Logger, crash_handler: CrashHandler, user_manager: UserManager, tnfs: TNFS, selinux: SELinux)`
- **Описание**: Инициализирует ядро.
- **Параметры**:
  - `logger`: Экземпляр `Logger`.
  - `crash_handler`: Экземпляр `CrashHandler`.
  - `user_manager`: Экземпляр `UserManager`.
  - `tnfs`: Экземпляр `TNFS`.
  - `selinux`: Экземпляр `SELinux`.
- **Действия**:
  - Инициализирует зависимости.
  - Создает пустые словари `processes` и `memory`.
  - Устанавливает `next_pid` для управления процессами.
  - Связывает `tnfs` и `selinux`.

### Методы
- **login(username: str, password: str) -> bool**: Выполняет вход пользователя через `UserManager`.
- **logout(session_id: int) -> bool**: Выполняет выход из сессии через `UserManager`.
- **add_user(username: str, password: str, role: str) -> bool**: Добавляет пользователя через `UserManager`.
- **delete_user(username: str) -> bool**: Удаляет пользователя через `UserManager`.
- **change_password(username: str, old_password: str, new_password: str) -> bool**: Изменяет пароль через `UserManager`.
- **get_active_sessions() -> List[Dict]**: Возвращает активные сессии через `UserManager`.
- **get_session_info(session_id: int) -> Dict**: Возвращает информацию о сессии через `UserManager`.
- **list_dir(path: str) -> List[str]**: Список содержимого директории через `TNFS`.
- **read_file(path: str) -> str**: Читает файл через `TNFS`.
- **create_file(path: str, content: str)**: Создает файл через `TNFS`.
- **create_directory(path: str)**: Создает директорию через `TNFS`.
- **remove(path: str)**: Удаляет файл или директорию через `TNFS`.
- **chmod(path: str, perms: int)**: Изменяет права доступа через `TNFS`.
- **rename(old_path: str, new_path: str)**: Переименовывает файл или директорию через `TNFS`.
- **copy(src_path: str, dst_path: str)**: Копирует файл или директорию через `TNFS`.
- **move(src_path: str, dst_path: str)**: Перемещает файл или директорию через `TNFS`.

## Логирование
- Логи сохраняются в `data/logs/kernel.log`.
- Пример:
  ```
  {"timestamp": "2025-06-27 23:19:26", "level": "INFO", "name": "kernel", "message": "Kernel initialized"}
  ```

## Замечания
- Инициализация `UserManager` и `TNFS` внутри `__init__` дублирует переданные аргументы, что может привести к несогласованности. Рекомендуется использовать переданные экземпляры.
- Поля `processes` и `memory` не используются в текущей реализации.

## Рекомендации
- Удалить дублирующую инициализацию в `__init__`:
  ```python
  self.user_manager = user_manager
  self.tnfs = tnfs
  self.selinux = selinux
  ```
- Добавить управление процессами и памятью для поддержки `processes` и `memory`.
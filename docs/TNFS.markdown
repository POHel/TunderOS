# Документация для модуля `TNFS.py`

## Описание
`TNFS.py` содержит класс `TNFS`, реализующий файловую систему TunderOS. Она использует SQLite для хранения метаданных файлов и поддерживает операции с файлами и директориями с проверкой прав доступа и SELinux.

## Зависимости
- Python 3.8+
- Модули Python: `sqlite3`, `time`, `pathlib`, `os`, `sys`
- Внутренние модули:
  - `libs.logging.Logger`
  - `libs.CrashHandler.CrashHandler`
  - `core.users.UserManager`
  - `security.SELinux.SELinux`

## Класс `TNFS`

### `__init__(self, logger: Logger, crash_handler: CrashHandler, user_manager: UserManager, selinux: Optional[SELinux])`
- **Описание**: Инициализирует файловую систему.
- **Параметры**:
  - `logger`, `crash_handler`, `user_manager`, `selinux`: Экземпляры соответствующих классов.
- **Действия**:
  - Создает SQLite базу данных `data/tnfs.db` с таблицами `inodes`, `files`, `journal`.
  - Вызывает `init_default_structure`.

### `init_default_structure(self)`
- **Описание**: Создает начальную структуру файловой системы (`/`, `/home`, `/etc`, `/bin`, `/var`, `/tmp`).

### `_create_inode(self) -> int`
- **Описание**: Создает новый инод.

### `_check_permissions(self, path: str, user: str, operation: str) -> bool`
- **Описание**: Проверяет права доступа на основе `chmod`.
- **Параметры**:
  - `path`: Путь.
  - `user`: Пользователь.
  - `operation`: Операция (`read`, `write`, `execute`).

### Методы для операций с файлами и директориями
- **create_directory(path: str, owner: str, perms: int) -> bool**
- **remove(path: str) -> bool**
- **rename_directory(old_path: str, new_path: str) -> bool**
- **copy_directory(src_path: str, dst_path: str) -> bool**
- **move_directory(src_path: str, dst_path: str) -> bool**
- **list_directory(path: str) -> List[str]**
- **create_file(path: str, content: str, owner: str, perms: int) -> bool**
- **read_file(path: str) -> Optional[str]**
- **write_file(path: str, content: str) -> bool**
- **rename_file(old_path: str, new_path: str) -> bool**
- **copy_file(src_path: str, dst_path: str) -> bool**
- **move_file(src_path: str, dst_path: str) -> bool**
- **chmod(path: str, perms: int) -> bool**

### `_log_journal(self, operation: str, path: str, details: str)`
- **Описание**: Логирует операцию в журнал.

## Логирование
- Логи сохраняются в `data/logs/tnfs.log`.
- Журнал операций в `data/tnfs.db` (таблица `journal`).

## Замечания
- Права доступа `0o1363` для `/` вызывают ошибку `Permission denied`. Рекомендуется использовать `0o755`.

## Рекомендации
- Исправить права для `/` в `init_default_structure`:
  ```python
  defaults = [("/", "", "root", 0o755, "directory", 0), ...]
  ```
- Добавить кэширование метаданных для оптимизации.
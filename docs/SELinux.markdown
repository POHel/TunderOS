# Документация для модуля `SELinux.py`

## Описание
`SELinux.py` содержит класс `SELinux`, который реализует систему контроля доступа на основе SELinux для TunderOS. Он управляет политиками доступа, проверяет права и ведет аудит операций.

## Зависимости
- Python 3.8+
- Модули Python: `json`, `sqlite3`, `time`, `pathlib`, `os`, `sys`
- Внутренние модули:
  - `libs.logging.Logger`
  - `libs.CrashHandler.CrashHandler`
  - `TNFS.TNFS`

## Класс `SELinux`

### `__init__(self, logger: Logger, crash_handler: CrashHandler, tnfs: TNFS)`
- **Описание**: Инициализирует SELinux.
- **Параметры**:
  - `logger`: Экземпляр `Logger`.
  - `crash_handler`: Экземпляр `CrashHandler`.
  - `tnfs`: Экземпляр `TNFS`.
- **Действия**:
  - Создает SQLite базу данных `data/selinux.db` с таблицей `selinux_audit`.
  - Загружает политики из `data/selinux_policies.json` или создает их по умолчанию.

### `set_mode(self, mode: str)`
- **Описание**: Устанавливает режим SELinux (`enforcing` или `permissive`).
- **Параметры**:
  - `mode`: Режим SELinux.
- **Действия**:
  - Проверяет валидность режима.
  - Обновляет `policies` и сохраняет в JSON.

### `check_access(self, path: str, operation: str, username: str, role: str, session_id: int) -> bool`
- **Описание**: Проверяет доступ к пути на основе политик SELinux.
- **Параметры**:
  - `path`: Путь.
  - `operation`: Операция (`read`, `write`, `execute`, `delete`).
  - `username`: Имя пользователя.
  - `role`: Роль пользователя.
  - `session_id`: ID сессии.
- **Возвращает**: `True`, если доступ разрешен, иначе вызывает `TunderCrash` в режиме `enforcing`.

### `add_rule(self, path: str, operation: str, roles: List[str], type_: str)`
- **Описание**: Добавляет правило SELinux.
- **Параметры**:
  - `path`: Путь.
  - `operation`: Операция.
  - `roles`: Список ролей.
  - `type_`: Тип объекта (`file`, `directory`).

### `remove_rule(self, path: str, operation: str, roles: List[str])`
- **Описание**: Удаляет правило SELinux.
- **Параметры**:
  - `path`, `operation`, `roles`: Аналогично `add_rule`.

### `list_rules(self) -> Dict`
- **Описание**: Возвращает текущие правила SELinux.

### `reset_policies(self)`
- **Описание**: Сбрасывает политики SELinux к значениям по умолчанию.

## Логирование
- Логи сохраняются в `data/logs/selinux.log`.
- Аудит операций в `data/selinux.db`.

## Замечания
- Проверка пути в `check_access` не поддерживает шаблоны (например, `/home/*`).

## Рекомендации
- Добавить поддержку шаблонов в `check_access`:
  ```python
  import fnmatch
  def check_access(self, path: str, operation: str, username: str, role: str, session_id: int) -> bool:
      for policy_path, rules in self.policies["rules"].items():
          if fnmatch.fnmatch(path, policy_path):
              if operation in rules and role in rules[operation]:
                  return True
  ```
- Реализовать очистку старых записей аудита.
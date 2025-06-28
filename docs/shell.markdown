# Документация для модуля `shell.py`

## Описание
`shell.py` содержит класс `Shell`, который реализует интерактивную оболочку TunderOS. Оболочка поддерживает команды для работы с файлами, пользователями, SELinux и сессиями, с цветным выводом и обработкой ошибок.

## Зависимости
- Python 3.8+
- Модули Python: `os`, `sys`, `html`, `pathlib`, `prompt_toolkit`
- Внутренние модули:
  - `core.TunKernel.Kernel`
  - `src.libs.logging.Logger`
  - `src.TNFS.TNFS`
  - `src.libs.CrashHandler.CrashHandler`

## Класс `Shell`

### `__init__(self, kernel: Kernel, logger: Logger, crash_handler: CrashHandler, tnfs: TNFS)`
- **Описание**: Инициализирует оболочку.
- **Параметры**:
  - `kernel`: Экземпляр `Kernel`.
  - `logger`: Экземпляр `Logger`.
  - `crash_handler`: Экземпляр `CrashHandler`.
  - `tnfs`: Экземпляр `TNFS`.
- **Действия**:
  - Создает привязки клавиш для `Ctrl+C`.
  - Выполняет вход для `root`.
  - Инициализирует `PromptSession`.

### `_handle_ctrl_c(self, event)`
- **Описание**: Обрабатывает нажатие `Ctrl+C`.
- **Действия**:
  - Выводит сообщение и завершает работу.

### `_help(self, args: List[str])`
- **Описание**: Выводит справку по командам.
- **Параметры**:
  - `args`: Список аргументов (опционально команда).
- **Действия**:
  - Выводит список всех команд или описание конкретной команды.

### `run(self)`
- **Описание**: Запускает цикл обработки команд.
- **Действия**:
  - Читает команды пользователя.
  - Выполняет команды (`ls`, `cat`, `L.mktxt`, `L.chmod`, `login`, и т.д.).
  - Обрабатывает ошибки с помощью `CrashHandler`.

### Поддерживаемые команды
- `L.mktxt <path>`: Создает текстовый файл.
- `L.mkdir <path>`: Создает директорию.
- `L.rm <path>`: Удаляет файл или директорию.
- `L.chmod <path> <perms>`: Изменяет права доступа.
- `L.rename <old_path> <new_path>`: Переименовывает файл или директорию.
- `L.copy <src_path> <dst_path>`: Копирует файл или директорию.
- `L.move <src_path> <dst_path>`: Перемещает файл или директорию.
- `cat <path>`: Выводит содержимое файла.
- `ls [path]`: Список содержимого директории.
- `adduser <username> <password> [role]`: Добавляет пользователя.
- `deluser <username>`: Удаляет пользователя.
- `passwd <username>`: Изменяет пароль.
- `login <username>`: Выполняет вход.
- `logout`: Выполняет выход.
- `who`: Показывает активные сессии.
- `whoami`: Показывает текущую сессию.
- `SEL <enforcing/permissive>`: Устанавливает режим SELinux.
- `addrule <path> <operation> <type> <subjects...>`: Добавляет правило SELinux.
- `rmrule <path> <operation> <subjects...>`: Удаляет правило SELinux.
- `listrules`: Показывает правила SELinux.
- `resetSEL`: Сбрасывает политики SELinux.
- `L.warn`: Триггерит тестовое предупреждение.
- `auditlogs`: Показывает логи аудита SELinux.
- `exit`: Выходит из оболочки.
- `help [command]`: Показывает справку.

## Логирование
- Логи сохраняются в `data/logs/shell.log`.
- Пример:
  ```
  {"timestamp": "2025-06-27 23:19:26", "level": "INFO", "name": "shell", "message": "Shell initialized"}
  ```

## Замечания
- Некоторые команды помечены как `!!!ERROR!!!` или `!!!DEV!!!` в `COMMANDS`, что указывает на незавершенность.
- Ошибка в `login`: `get_user_info` не используется корректно для получения роли.

## Рекомендации
- Исправить `login`, заменив:
  ```python
  self.tnfs.current_role = self.kernel.user_manager.get_user_info(username)['role']
  ```
- Добавить автодополнение команд:
  ```python
  from prompt_toolkit.completion import WordCompleter
  self.completer = WordCompleter(list(self.COMMANDS.keys()), ignore_case=True)
  self.session = PromptSession(f"~{self.tnfs.current_user}--> ", key_bindings=self.bindings, completer=self.completer)
  ```
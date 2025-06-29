# Документация для модуля `start.py`

## Описание
`start.py` является точкой входа для операционной системы TunderOS. Этот модуль отвечает за инициализацию всех компонентов системы, включая логгер, обработчик ошибок, файловую систему, менеджер пользователей, SELinux и оболочку. Он также обрабатывает аргументы командной строки для настройки режима отладки и начального режима SELinux.

## Зависимости
- Python 3.8+
- Модули Python: `argparse`, `sys`, `os`, `pathlib`
- Внутренние модули:
  - `src.libs.logging.Logger`
  - `src.libs.CrashHandler.CrashHandler`
  - `src.core.TunKernel.Kernel`
  - `src.core.users.UserManager`
  - `src.TNFS.TNFS`
  - `src.security.SELinux.SELinux`
  - `src.shell.shell.Shell`

## Функции и методы

### `parse_args()`
- **Описание**: Разбирает аргументы командной строки.
- **Аргументы**:
  - `--debug`: Включает отладочное логирование (булевый флаг).
  - `--mode`: Устанавливает начальный режим SELinux (`enforcing` или `permissive`, по умолчанию `permissive`).
- **Возвращает**: Объект `argparse.Namespace` с разобранными аргументами.
- **Логирование**: Логирует запуск системы через `Logger`.

### `main()`
- **Описание**: Основная функция, выполняющая запуск TunderOS.
- **Процесс**:
  1. Парсит аргументы командной строки.
  2. Инициализирует логгер (`Logger`) с именем `"system"`.
  3. Создает обработчик ошибок (`CrashHandler`).
  4. Инициализирует менеджер пользователей (`UserManager`).
  5. Инициализирует файловую систему (`TNFS`).
  6. Инициализирует SELinux (`SELinux`) и связывает его с `TNFS` и `UserManager`.
  7. Инициализирует ядро (`Kernel`).
  8. Выполняет автоматический вход для пользователя `root` с паролем `"root"`.
  9. Устанавливает начальный режим SELinux на основе аргумента `--mode`.
  10. Запускает оболочку (`Shell`) и переходит в цикл обработки команд.
- **Обработка ошибок**:
  - Обрабатывает исключения `TunderCrash` и другие через `CrashHandler`.
  - Завершает работу с кодом выхода `1` при критических ошибках.
- **Логирование**:
  - Логирует запуск системы, инициализацию компонентов и установку режима SELinux.

## Использование
```bash
python start.py --debug --mode enforcing
```
- Включает отладочное логирование и устанавливает SELinux в режим `enforcing`.

## Логирование
- Логи сохраняются в `data/logs/system.log`.
- Пример лога:
  ```
  {"timestamp": "2025-06-27 23:19:26", "level": "INFO", "name": "system", "message": "Starting Tunder OS"}
  ```

## Замечания
- Автоматический вход для `root` использует пароль `"root"`, что требует доработки для повышения безопасности.
- Модуль зависит от корректной инициализации всех компонентов, поэтому ошибки в зависимостях (например, отсутствие базы данных) могут привести к сбоям.

## Рекомендации
- Добавить проверку существования файлов баз данных перед инициализацией.
- Реализовать конфигурационный файл для задания начальных параметров вместо аргументов командной строки.
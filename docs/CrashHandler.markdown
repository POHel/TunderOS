# Документация для модуля `CrashHandler.py`

## Описание
`CrashHandler.py` содержит классы `TunderCrash` и `CrashHandler`, которые управляют обработкой ошибок и предупреждений в TunderOS. `CrashHandler` создает crash-дампы и логирует ошибки.

## Зависимости
- Python 3.8+
- Модули Python: `os`, `sys`, `time`, `json`, `pathlib`
- Внутренние модули: `libs.logging.Logger`

## Класс `TunderCrash(Exception)`

### `__init__(self, code: str, message: str, category: str, details: str = "")`
- **Описание**: Пользовательское исключение для ошибок TunderOS.
- **Параметры**:
  - `code`: Код ошибки (например, `0xA0E0ERR`).
  - `message`: Описание ошибки.
  - `category`: Категория ошибки (`ERROR`, `WARNING`, `SYSTEM`, `FS`, `SELINUX`, `NETWORK`, `SYNTAX`).
  - `details`: Дополнительные детали.

## Класс `CrashHandler`

### `__init__(self, logger: Logger, kernel=None)`
- **Описание**: Инициализирует обработчик ошибок.
- **Параметры**:
  - `logger`: Экземпляр `Logger`.
  - `kernel`: Экземпляр `Kernel` (опционально).
- **Действия**:
  - Создает директорию `data/crash`.

### `raise_crash(self, category: str, code: str, details: str = "")`
- **Описание**: Вызывает исключение `TunderCrash` и логирует его.
- **Параметры**:
  - `category`: Категория ошибки.
  - `code`: Код ошибки.
  - `details`: Дополнительные детали.
- **Действия**:
  - Логирует ошибку или предупреждение.
  - Создает crash-дамп для ошибок (не для предупреждений).

### `handle(self, exception: Exception, context: str = "", critical: bool = False)`
- **Описание**: Обрабатывает исключения Python и `TunderCrash`.
- **Параметры**:
  - `exception`: Исключение.
  - `context`: Контекст ошибки.
  - `critical`: Флаг критической ошибки.
- **Действия**:
  - Проверяет рекурсию с помощью `_handling_error`.
  - Логирует ошибку с соответствующим кодом и категорией.
  - Создает crash-дамп для критических ошибок.

### `warn(self, category: str, code: str, details: str = "")`
- **Описание**: Логирует предупреждение.
- **Параметры**:
  - `category`: Категория (`WARNING`).
  - `code`: Код предупреждения.
  - `details`: Дополнительные детали.

### `_create_crash_dump(self, category: str, code: str, message: str, details: str)`
- **Описание**: Создает crash-дамп в формате JSON.
- **Параметры**:
  - `category`, `code`, `message`, `details`: Параметры ошибки.
- **Действия**:
  - Сохраняет дамп в `data/crash/{timestamp}.json` с информацией о пользователе, процессах и памяти.

## Логирование
- Логи сохраняются в `data/logs/{name}.log`.
- Crash-дампы сохраняются в `data/crash/{timestamp}.json`.

## Замечания
- Поле `kernel` используется только в `_create_crash_dump`, но не проверяется на `None`.

## Рекомендации
- Добавить проверку `kernel` на `None` в `_create_crash_dump`.
- Реализовать механизм уведомления администратора о критических ошибках.
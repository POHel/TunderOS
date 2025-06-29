# Документация для модуля `logging.py`

## Описание
`logging.py` содержит класс `Logger`, который обеспечивает логирование операций в TunderOS. Логи записываются в файлы JSON и выводятся в консоль с цветным форматированием.

## Зависимости
- Python 3.8+
- Модули Python: `json`, `os`, `time`, `pathlib`, `colorama`
- Внутренние модули: Нет

## Класс `Logger`

### `__init__(self, name: str, max_size: int = 10*1024*1024)`
- **Описание**: Инициализирует логгер.
- **Параметры**:
  - `name`: Имя логгера (используется в имени файла логов).
  - `max_size`: Максимальный размер лог-файла (по умолчанию 10 МБ).
- **Действия**:
  - Создает директорию `data/logs`, если она не существует.
  - Устанавливает путь к файлу логов `data/logs/{name}.log`.

### `_rotate(self)`
- **Описание**: Выполняет ротацию логов, если файл превышает `max_size`.
- **Действия**:
  - Переименовывает текущий лог-файл, добавляя временную метку.

### `_write(self, level: str, message: str)`
- **Описание**: Записывает сообщение в лог-файл и консоль.
- **Параметры**:
  - `level`: Уровень лога (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`).
  - `message`: Сообщение для записи.
- **Действия**:
  - Вызывает `_rotate` для проверки размера файла.
  - Формирует JSON-запись с `timestamp`, `level`, `name`, `message`.
  - Выводит сообщение в консоль с цветом, соответствующим уровню.

### `debug(self, message: str)`, `info(self, message: str)`, `warning(self, message: str)`, `error(self, message: str)`, `critical(self, message: str)`
- **Описание**: Методы для записи сообщений на разных уровнях логирования.
- **Параметры**:
  - `message`: Сообщение для записи.
- **Действия**:
  - Вызывают `_write` с соответствующим уровнем.

## Логирование
- Логи сохраняются в `data/logs/{name}.log` в формате JSON.
- Пример лога:
  ```
  {"timestamp": "2025-06-27 23:19:26", "level": "INFO", "name": "system", "message": "Starting Tunder OS"}
  ```
- Цвета в консоли:
  - `DEBUG`: Белый
  - `INFO`: Зеленый
  - `WARNING`: Желтый
  - `ERROR`: Красный
  - `CRITICAL`: Пурпурный

## Замечания
- Ротация логов не очищает старые файлы, что может привести к накоплению.

## Рекомендации
- Добавить механизм автоматической очистки старых логов.
- Поддержать настройку уровня логирования через аргументы или конфигурацию.
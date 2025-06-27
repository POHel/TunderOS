#bootloader
import argparse
import sys
from pathlib import Path
import os

# Настройка пути для импорта модулей
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)

from src.libs.logging import Logger
from src.libs.CrashHandler import CrashHandler, TunderCrash
from src.core.TunKernel import Kernel
from src.core.users import UserManager
from src.TNFS.TNFS import TNFS
from src.security.SELinux import SELinux
from src.shell.shell import Shell


def parse_args():
    """Разбирает аргументы командной строки."""
    parser = argparse.ArgumentParser(description="Tunder OS")
    parser.add_argument("--debug", action="store_true", help="Включить отладочное логирование")
    parser.add_argument("--mode", choices=["enforcing", "permissive"], default="permissive",
                        help="Установить начальный режим SELinux")
    return parser.parse_args()

def main():
    """Точка входа для Tunder OS."""
    try:
        # Парсинг аргументов
        args = parse_args()

        # Инициализация логгера
        logger = Logger("system")
        logger.info("Starting Tunder OS")

        # Инициализация обработчика ошибок
        crash_handler = CrashHandler(logger)

        # Инициализация UserManager
        user_manager = UserManager(logger, crash_handler)

        # Инициализация TNFS
        tnfs = TNFS(logger, crash_handler, user_manager)

        # Инициализация SELinux
        selinux = SELinux(logger, crash_handler, tnfs)
        tnfs.selinux = selinux  # Связываем SELinux с TNFS
        user_manager.tnfs = tnfs  # Связываем TNFS с UserManager

        # Инициализация ядра
        kernel = Kernel(logger, crash_handler, user_manager, tnfs, selinux)
        
        # Автоматический вход для root
        user_manager.login("root", "root")
        logger.info("Root user logged in automatically")

        # Установка начального режима SELinux
        selinux.set_mode(args.mode)
        logger.info(f"SELinux mode set to {args.mode}")

        # Инициализация оболочки
        shell = Shell(kernel, logger, crash_handler, tnfs)
        logger.info("Shell initialized")

        # Запуск оболочки
        shell.run()

    except TunderCrash as e:
        logger.error(f"Critical error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        crash_handler.handle(e, "System startup")
        sys.exit(1)

if __name__ == "__main__":
    main()
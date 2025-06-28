#bootloader
import argparse
import sys
from pathlib import Path
import os
import time

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

AAU = False
AAR = False

def parse_args():
    """Разбирает аргументы командной строки."""
    parser = argparse.ArgumentParser(description="Tunder OS")
    parser.add_argument("--debug", action="store_true", help="Включить отладочное логирование")
    parser.add_argument("--mode", choices=["enforcing", "permissive"], default="permissive",
                        help="Установить начальный режим SELinux")
    return parser.parse_args()

def main():
    """Точка входа для Tunder OS."""
    print('Starting TunderOS')
    try:
        # Парсинг аргументов
        print('Parsing arguments...')
        args = parse_args()
        print('Parsing arguments...DONE')

        # Инициализация логгера
        print('Initialize logger from system...')
        logger = Logger("system")
        logger.info("Starting Tunder OS")
        print('Logger from system...Initialized')

        # Инициализация обработчика ошибок
        print('Initialize CrashHandler...')
        crash_handler = CrashHandler(logger)
        print('CrashHandler...Initialized')

        # Инициализация UserManager
        print('Initialize UserManager...')
        user_manager = UserManager(logger, crash_handler)
        print('UserManager...Initialized')

        # Инициализация TNFS
        print('Initialize TNFS-(TunderFileSystem)...')
        tnfs = TNFS(logger, crash_handler, user_manager)
        print('TNFS...Initialized')

        # Инициализация SELinux
        print('Initialize SELinux...')
        selinux = SELinux(logger, crash_handler, tnfs)
        print('Linkin SELinux with TNFS...')
        tnfs.selinux = selinux  # Связываем SELinux с TNFS
        print('Linkin SELinux with TNFS...DONE')
        print('Linkin TNFS with UserManager...')
        user_manager.tnfs = tnfs  # Связываем TNFS с UserManager
        print('Linkin TNFS with UserManager...DONE')
        print('SELinux...Initialized')

        # Инициализация ядра
        print('Initialize TunderKernel...')
        kernel = Kernel(logger, crash_handler, user_manager, tnfs, selinux)
        print('TunderKernel...Initialized')
        print('Skipping Auto Auth...')
        """
        try:
            if AAU == True:
                #Автоматический вход для user
                user_manager.login("user", "user")
                logger.info("User logged in automatically")
            elif AAR == True:
                #Автоматический вход для root
                user_manager.login("root", "root")
                logger.info("Root user logged in automatically")
            else:
                print('Skipping Auto Auth...')
        except:
            logger.error("Error on AA(Auto Auth)")        
        """
        # Установка начального режима SELinux
        print('Setting the initial SELinux mode...')
        selinux.set_mode(args.mode)
        logger.info(f"SELinux mode set to {args.mode}")
        print('Setting the initial SELinux mode...DONE')

        # Инициализация оболочки
        print('Initialize Shell ...')
        shell = Shell(kernel, logger, crash_handler, tnfs)
        logger.info("[LOG]Start-->Shell initialized")
        print('Start-->Shell initialized')

        # Запуск оболочки
        print('Starting Shell')
        shell.run()

    except TunderCrash as e:
        logger.error(f"Critical error: {str(e)}")
        sys.exit(1)
    except Exception as e:
        crash_handler.handle(e, "System startup")
        sys.exit(1)

if __name__ == "__main__":
    main()
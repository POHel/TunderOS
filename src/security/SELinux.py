#created by Antarctica
import json
from pathlib import Path
from typing import List, Optional
import sys
import os
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from libs.logging import Logger
from libs.CrashHandler import CrashHandler, TunderCrash

BASE_DIR = Path(__file__).resolve().parent.parent.parent #Определяем базовый путь для проекта, используя переменную file, которая должна быть определена ранее в коде. Мы переходим на три уровня вверх по директориям.
SELinux_CONFIG = BASE_DIR / "data" / "selinux.json" #Определяем путь к файлу конфигурации SELinux в формате JSON.

class SELinux:
    def __init__(self, Logger: Logger, crash_handler: CrashHandler): #Определяем метод инициализации класса, который принимает экземпляры логгера и обработчика ошибок.
        self.logger = Logger #Сохраняем переданный логгер в атрибуте экземпляра.
        self.crash_handler = crash_handler #Такое же сохранение
        self.politices = self._load_politices() #загружаем политики SELinux из файла (или создаем их по умолчанию).
        self.mode = self.politices.get("mode", "permissive") #Получаем режим работы SELinux, по умолчанию — "permissive".
        self.logger.info(f"SELinux intialized in {self.mode} mode") #Логируем информацию о том, что SELinux инициализирован.

    def _load_politicies(self) -> dict: #Определяем метод для загрузки политик SELinux, возвращающий словарь.
        try:
            if SELinux_CONFIG.exists(): #Проверяем, существует ли файл конфигурации.
                with open (SELinux_CONFIG, "r", encoding="utf-8") as f: #Открываем файл для чтения.
                    politicies = json.load(f) #Загружаем политики из файла.
                    self.logger.info("Loaded SELinux politicies") #Логируем информацию о загрузке политик.
                    return politicies
        except (json.JSONDecodeError, IOError)as e: #Обрабатываем исключения при загрузке JSON или ввода-вывода.
            self.crash_handler.handle(e, "Loading SELinux politicies") #Обрабатываем ошибку с помощью обработчика ошибок.

#Создание и сохранение политик по умолчанию
        default_policies ={ #Определяем стандартные политики SELinux в виде словаря.
            "mode": "permissive",
            "rules": {
                "/": {"read": ["root", "user"], "write": ["root"], "execute": ["root"], "delete": ["root"]},
                "/home": {"read": ["root", "user"], "write": ["root", "user"], "execute": ["root"], "delete": ["root"]}
            }
        }
        self._save_politicies(default_policies) #Сохраняем стандартные политики в файл.
        self.logger.info("Created default SELinux politicies") #Логируем информацию о создании стандартных политик.
        return default_policies
    
#Метод сохранения политик
    def _save_politicies(self, politicies: dict): #Определяем метод для сохранения политик в файл.
        SELinux.parent.mkdir(parents=True, exist_ok=True) #Создаем директорию для файла конфигурации (если она не существует).
        with open(SELinux_CONFIG, "w", encoding="utf-8") as f: #Открываем файл для записи.
            json.dump(politicies,f, indent=2) #Записываем политики в формате JSON с отступами.
        self.logger.info("Saved SELinux politicies") #Логируем информацию о сохранении политик.

#Метод проверки доступа
    def check_access(self, path: str, operation: str, user: str, role: str) -> bool: #Определяем метод для проверки доступа к ресурсу на основе заданных параметров.
        pass

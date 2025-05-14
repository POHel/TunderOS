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
        if self.mode == "permissive": #Если режим SELinux установлен на "permissive", то доступ всегда предоставляется, и информация об этом записывается в лог.
            self.logger.info(f"SELinux (permissive): {user} ({role}) requests {operation} on {path}")
            return True
        
        rules = self.policies.get("rules", {}).get(path,{}) #Извлекаются правила для запрашиваемого пути.
        allowed_subjects = rules.get(operation, []) #Если правил нет, возвращается пустой словарь. Затем извлекаются разрешенные субъекты для запрашиваемой операции (например, чтение, запись и т.д.

        if user in allowed_subjects or role in allowed_subjects: #Если пользователь или его роль присутствуют в списке разрешенных субъектов, доступ предоставляется, и это записывается в лог.
            self.logger.info(f"SELinux: Granted {operation} on {PATH} for {user} ({role})")
            return True
        
        self.logger.warning(f"SELinux: Denied {operation} on {path} for {user} ({role})") #Если доступ не предоставлен, генерируется предупреждение в логах.
        if self.mode == "enforcing": #Если режим SELinux установлен на "enforcing", вызывается обработчик сбоев, который может завершить работу программы или выполнить другие действия. Возвращается значение False, указывающее на отказ в доступе.
            self.crash_handler.raise_crash("SELinux", "0xSAD0ERR", f"SELinux acces denied {operation} on {path} for {user}")
            return False
    
    def set_mode(self, mode: str): #Метод устанавливает режим SELinux. Если переданный режим не является допустимым ("enforcing" или "permissive"), вызывается обработчик сбоев.
        if mode not in ["enforcing", "permissive"]:
            self.crash_handler.raise_crash("SELinux", "0xSIM0ERR", f"Invalid SELinux mode: {mode}" )
            self.mode = mode #Если режим допустим, он сохраняется в атрибуте объекта и обновляется в политике. Затем изменения сохраняются.
            self.politices["mode"] = mode
            self._save_politicies(self.politices)
            self.logger.info(f"SELinux mode changed to  {mode}") #Записывается информация о том, что режим SELinux был изменен.

    def add_rule(self, path: str, operation: str, subjects: List[str]): #Метод добавляет правило для указанного пути и операции. Если операция недопустима, вызывается обработчик сбоев.
        if operation not in ["read", "write", "execute", "delete"]:
            self.crash_handler.raise_crash("SELinux", "0xSIO0ERR" f"Invalid operation: {operation}")
        if path not in  self.politices["rules"]: #Если для указанного пути еще нет правил, создается новая структура для всех операций.
            self.politices["rules"][path] = {"read": [], "write": [], "execute": [], "delete": []}
            self.politices["rules"][path][operation] = list(set(self.politices["rules"][path][operation] + subjects)) #Субъекты добавляются к списку разрешенных для данной операции. Используется set для удаления дубликатов.
            self._save_politicies(self.politices) #Политики сохраняются, и информация об успешном добавлении правила записывается в лог.
            self.logger.info(f"Added SELinux rule: {operation} on {path} for {subjects}")

    def remove_rule(self, path: str, operation: str, subjects: list[str]): #Метод удаляет правило для указанного пути и операции. Проверяется наличие правил.
        if path in self.politices["rules"] and operation in self.politices["rules"][path]:
            self.politices["rules"][path][operation] = [s for s in self.politices["rules"][path][operation] if s not in subjects] #Из списка разрешенных субъектов удаляются те, которые указаны в параметре subjects.
            self._save_politicies(self.politices) #Политики сохраняются, и информация об успешном удалении правила записывается в лог.
            self.logger.info(f"Removed SELinux rule: {operation} on {path} for {subjects}")
        else: #Если правило не найдено, вызывается обработчик сбоев с соответствующим сообщением.
            self.crash_handler.raise_crash("SELINUX", "0xSRN0ERR", f"No rule found for {operation} on {path}")
    
    def reset_politicies(self): #Метод сбрасывает политики к значениям по умолчанию. Режим устанавливается на "permissive", а правила определяются для корневого пути.
        self.politices = {
            "mode": "permissive",
            "rules": {
                "/": {"read": ["root", "user"], "write": ["root"], "execute": ["root"], "delete": ["root"]}
            }
        }
        self._save_politicies(self.politices) #Политики сохраняются, режим устанавливается на "permissive", и информация о сбросе записывается в лог.
        self.mode = "permissive"
        self.logger.info("SELinux politicies reset to default")

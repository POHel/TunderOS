#CrashHandler
#created by SKATT
import os
import sys
import time
import json
from pathlib import Path
from typing import Optional, Dict, List
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) #вычисляет путь к каталогу, который находится на два уровня выше текущего файла
sys.path.append(INIT_DIR) #перемещение в папку библиотек
from libs.Logging import Logger

BASE_DIR = Path(__file__).resolve().parent.parent.parent #использует библиотеку pathlib для получения пути к каталогу, который находится на три уровня выше текущего файла
CRASH_DIR = BASE_DIR / "data" / "crash"

class TunderCrash(Exception): #инициализация 
    def __init__(self, code: str, message: str, category: str, details: str = ""):
        self.code = code
        self.message = message
        self.category = category
        self.details = details
        super().__init__(f"[{code}] {category}: {message} {details}")

class CrashHandler:
    # перечисление всех возможных кодов и ошибок а так же присваивание к ним идентификатора кода ошибки
    ERROR_CODES = {
        "ERROR": {
            "0xA0E0ERR": "ArithmeticError - Base class for arithmetic errors",
            "0xF0E0ERR": "FloatingPointError - Floating point operation failed",
            "0xO0E0ERR": "OverflowError - Result too large to be represented",
            "0xZ0E0ERR": "ZeroDivisionError - Division or modulo by zero",
            "0xS0E0ERR": "AssertionError - Assertion failed",
            "0xT0E0ERR": "AttributeError - Attribute not found or invalid",
            "0xB0E0ERR": "BufferError - Buffer operation failed",
            "0xE0E0ERR": "EOFError - End of file reached unexpectedly",
            "0xI0E0ERR": "ImportError - Failed to import module or name",
            "0xM0E0ERR": "ModuleNotFoundError - Module not found",
            "0xL0E0ERR": "LookupError - Base class for lookup errors",
            "0xK0E0ERR": "KeyError - Key not found in dictionary",
            "0xN0E0ERR": "IndexError - Sequence index out of range",
            "0xR0E0ERR": "ReferenceError - Weak reference callback failed",
            "0xU0E0ERR": "UnboundLocalError - Local variable referenced before assignment",
            "0xV0E0ERR": "ValueError - Operation or function received invalid value",
            "0xC0E0ERR": "UnicodeError - Unicode-related error",
            "0xD0E0ERR": "UnicodeDecodeError - Unicode decoding failed",
            "0xP0E0ERR": "UnicodeEncodeError - Unicode encoding failed",
            "0xQ0E0ERR": "UnicodeTranslateError - Unicode translation failed",
            "0xY0E0ERR": "TypeError - Operation or function applied to wrong type",
            "0xW0E0ERR": "NameError - Name not found in namespace",
            "0xX0E0ERR": "RuntimeError - General runtime error",
            "0xJ0E0ERR": "NotImplementedError - Abstract method not implemented",
            "0xH0E0ERR": "RecursionError - Maximum recursion depth exceeded",
            "0xG0E0ERR": "OSError - Operating system error",
            "0xF0N0F0ERR": "FileNotFoundError - File or directory not found",
            "0xP0D0ERR": "PermissionError - Permission denied",
            "0xI0D0ERR": "IsADirectoryError - Expected file, found directory",
            "0xN0D0ERR": "NotADirectoryError - Expected directory, found file",
            "0xB0I0ERR": "BlockingIOError - Operation would block",
            "0xC0N0ERR": "ConnectionError - Connection-related error",
            "0xC0R0ERR": "ConnectionRefusedError - Connection refused by peer",
            "0xT0M0ERR": "TimeoutError - Operation timed out",
            "0xM0M0ERR": "MemoryError - Out of memory",
            "0xE0N0ERR": "EnvironmentError - Environment-related error (legacy)"
        },
        "WARNING": {
            "0xW0W0WRN": "Warning - Base class for warnings",
            "0xB0W0WRN": "BytesWarning - Bytes-related warning",
            "0xD0W0WRN": "DeprecationWarning - Deprecated feature used",
            "0xF0W0WRN": "FutureWarning - Feature will change in future",
            "0xI0W0WRN": "ImportWarning - Issue with module import",
            "0xP0W0WRN": "PendingDeprecationWarning - Feature to be deprecated",
            "0xR0W0WRN": "ResourceWarning - Resource usage issue",
            "0xS0W0WRN": "SyntaxWarning - Suspicious syntax",
            "0xU0W0WRN": "UnicodeWarning - Unicode-related warning",
            "0xR0W0WRN": "RuntimeWarning - Suspicious runtime behavior",
            "0xU0W0WRN": "UserWarning - User-defined warning"
        },
        "SYSTEM": {
            "0xG0X0EXT": "GeneratorExit - Generator closed unexpectedly",
            "0xK0X0EXT": "KeyboardInterrupt - Program interrupted by user",
            "0xS0X0EXT": "SystemExit - Program requested to exit",
            "0xI0M0ERR": "Module import failed",
            "0xU0A0ERR": "User already exists",
            "0xA0F0ERR": "Authentication failed",
            "0xP0N0ERR": "Process not found"
        },
        "SYNTAX": {
            "0xS0E0ERR": "SyntaxError - Invalid syntax",
            "0xI0E0ERR": "IndentationError - Incorrect indentation",
            "0xT0E0ERR": "TabError - Inconsistent use of tabs and spaces"
        },
        "NETWORK": {
            "0xC0F0ERR": "Connection failed"
        },
        "SELINUX": {
            "0xSAD0ERR": "SELinux access denied",
            "0xSIM0ERR": "Invalid SELinux mode",
            "0xSIO0ERR": "Invalid SELinux operation",
            "0xSRN0ERR": "SELinux rule not found"
        },
        "FS": {
            "0xFNF0ERR": "File not found",
            "0xPNF0ERR": "Path not found",
            "0xPDN0ERR": "Permission denied",
            "0xDNE0ERR": "Directory not empty"
        }
    }

    def __init__(self, logger: Logger, kernel=None): # инициализация
        self.logger = logger
        self.kernel = kernel
        CRASH_DIR.mkdir(parents=True, exist_ok=True) # создание Crash директории

    def raise_crash(self, category: str, code: str, details: str = ""): # вызывает TunderCrash и регистрирует ошибку
        message = self.ERROR_CODES.get(category, {}).get(code, "Unknown error")
        full_message = f"{message} {category}".strip()
        if category == "WARNING":
            self.logger.warning(f"[{code}] {category}: {full_message}")
        else:
            self.logger.error(f"[{code}] {category}: {full_message}")
            self._create_crash_dump(category, code, message, details)
            raise TunderCrash(code, message, category, details)
    
    def handle(self, exception: Exception, context: str = "", critical: bool = False): # обрабатывает исключения, регистрирует и создаёт дамп
        if isinstance(exception, TunderCrash):
            self.logger.error(f"[{exception.code}] {exception.category}: {exception.message} {exception.details}")
        else: # попытка сопоставить встроенное исключение с кодом
            exc_name = type(exception).__name__
            code = None
            category = "ERROR"
            for cat, codes in self.ERROR_CODES.items():
                for c, msg in codes.items():
                    if msg.startswitch(exc_name):
                        code = c
                        category = cat
                        break
                if code:
                    break
            if not code:
                code = "0xR0E0ERR" #RuntimeError как запасной вариант
                category = "ERROR"
            message = self.ERROR_CODES[category].get(code, "Unknown error")
            full_message = f"{message}: {str(exception)} ({context})"
            if category == "WARNING":
                self.logger.warning(f"[{code}] {category}: {full_message}")
            else:
                self.logger.error(f"[{code}] {category}: {full_message}")
                if critical:
                    self._create_crush_dump(category, code, message, str(exception))

    def warn(self, category: str, code: str, details: str = ""): # логирует предупреждения без выброса исключения
        if category != "WARNING":
            self.logger.warning(f"Invalid warning category: {category}")
            return
        message = self.ERROR_CODES.get(category, {}).get(code, "Unknown warning")
        full_message = f"{message} {details}".strip()
        self.logger.warning(f"[{code}] {category}: {full_message}")

    def _create_rash_dump(self, category: str, code: str, message: str, details: str): # создаёт дамп состояния системы при сбое
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        dump_file = CRASH_DIR / f"{timestamp}.json"
        dump_data = {
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "category": category,
            "code": code,
            "message": message,
            "details": details,
            "user": getattr(self.kernel.tnfs, "current_user", "unknown") if self.kernel else "unknown",
            "role": getattr(self.kernel.tnfs, "current_role", "unknown") if self.kernel else "unknown",
            "processes": [
                {"pid": pid, "name": proc["name"], "state": proc["state"]}
                for pid, proc in getattr(self.kernel, "processes", {}).items()
            ],
            "memory": getattr(self.kernel, "memory", {}),
            "tnfs_state": self.kernel.tnsf.list_dir("/") if self.kernel else []
        }
        try:
            with open(dump_file, "w", encoding="utf-8") as f:
                json.dump(dump_data, f, indent=2)
            self.logger.info(f"Created crash dump: {dump_file}")
        except IOError as e:
            self.logger.error(f"Failed to create crash dump: {str(e)}")
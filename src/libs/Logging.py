#Logging lib
import json
import os
import time
from colorama import Fore, init
from pathlib import Path

init(autoreset=True)
INIT_DIR = Path(__file__).resolve().parent.parent.parent
LOG_DIR = INIT_DIR / "data" / "logs"

class Logger:
    LEVELS = {
        "DEBUG": (10, Fore.WHITE),
        "INFO": (20, Fore.GREEN),
        "WARNING": (30, Fore.YELLOW),
        "ERROR": (40, Fore.RED),
        "CRITICAL": (50, Fore.MAGENTA)
    }

    def __init__(self, name: str, max_size: int = 10*1024*1024):#максимальный размер log файла 10 мегабайт
        self.name = name
        self.max_size = max_size
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self.log_file = LOG_DIR / f"{name}.log"

    def _rotate(self):
        if self.log_file.exists() and self.log_file.stat().st_size > self.max_size:
            timestamp = time.strftime("%Y%m%d_%H%M%S")
            self.log_file.rename(self.log_file.with_suffix(f"{timestamp}.log"))

    def _write(self, level: str, message: str):
        self._rotate()
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_entry = {
            "timestamp": timestamp,
            "level": level,
            "name": self.name,
            "message": message
        }
        with open(self.log_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(log_entry) + "\n")
            color = self.LEVELS[level][1]
            print(f"[{timestamp}] {color}{level}: {message}{Fore.RESET}")
        
    def debug(self, message: str):
        if self.LEVELS["DEBUG"][0] >= 10:
            self._write("DEBUG", message)

    def info(self, message: str):
        self._write("INFO", message)

    def warning(self, message: str):
        self._write("WARNING", message)

    def error(self, message: str):
        self._write("ERROR", message)

    def critical(self, message: str):
        self._write("CRITICAL", message)

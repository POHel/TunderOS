#TUnderFileSystem
#created by SKATT
import sqlite3
import time
from pathlib import Path
from typing import List, Optional
import os
import sys
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from libs.Logging import Logger
from libs.CrashHandler import CrashHandler, TunderCrash
from core.users import UserManager
from security.SELinux import SELinux

BASE_DIR = Path(__file__).resolve().parent.parent.parent

class TNFS:
    def __init__(self, logger: Logger, crash_handler: CrashHandler, user_manager: UserManager, selinux: SELinux):
        self.logger = logger
        self.crash_handler = crash_handler
        self.user_manager = user_manager
        self.selinux = selinux
        self.db = sqlite3.connect(BASE_DIR / "data" / "tnfs.db")
        self.db.execute("CREATE TABLE IF NOT EXISTS inodes (inode INTEGER PRIMARY KEY AUTOINCREMENT, ref_count INTEGER DEFAULT 1)")
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS files (
                path TEXT PRIMARY KEY,
                inode INTEGER,
                content TEXT,
                owner TEXT,
                perms INTEGER,
                type TEXT CHECK(type IN ('file', 'directory')),
                size INTEGER,
                ctime REAL,
                mtime REAL,
                FOREIGN KEY(inode) REFERENCES inodes(inode)
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS journal (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                operation TEXT,
                path TEXT,
                timestamp REAL,
                details TEXT
            )
        """)
        self.db.execute
        self.current_user = "root"
        self.current_role = "root"
        self.init_default_structure()
        self.logger.info("Tunder File System initialized")
    
    def init_default_structure(self): # создаёт базовую структура файловой системы
        defaults = [
            ("/", "", "root", 755, "directory", 0),
            ("/home", "", "root", 755, "directory", 0),
            ("/etc", "", "root", 755, "directory", 0),
            ("/bin", "", "root", 755, "directory", 0)
        ]
        for path, content, owner, perms, type_, size in defaults:
            if not self.db.execute("SELECT path FROM files WHERE path = ?", (path)).fetchone():
                inode = self._create_inode()
                ctime = mtime = time.time()
                self.db.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (path, inode, content, owner, perms, type_, size, ctime, mtime)
                )
                self._log_journal("create", path, f"Created {type_}: {path}")
            self.db.commit()
            self.logger.info("Default TNFS structure initialized")

    def _create_inode(self) -> int: # создаёт новый inode
        cursor = self.db.execute("INSERT INTO inodes (ref_count) VALUES (1)")
        self.db.commit()
        return cursor.lasrowid
    
    def _check_primisions(self, path: str, user: str, operation: str) -> bool: #проверяет права доступа
        cursor = self.db.execute("SELECT owner, perms FROM files WHERE path = ?", (path,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("FS", "0xPNF0ERR", f"path not found: {path}")
        owner, perms = result
        perms_str = f"{perms:03o}"
        if user == owner or user == "root":
            return operation in {"read": "4", "write": "2", "execute": "1"} and perms_str[0] >= {"read": "4", "write": "2", "execute": "1"}[operation]
        return operation in {"read": "4", "execute": "1"} and perms_str[2] >= {"read": "4", "execute": "1"}[operation]

    def _log_journal(self, ): # Логирование операций в журнал
        self.db.execute("INSERT INFO journal (operation, path, timestamp, details)", (operation, path, time.time(), details))
        self.db.commit()

#Folders
    def create_directory(): # создание директорий
        pass

    def remove_directory(): # удаление дерикторий
        pass

    def rename_directory(): # переименование дерикторий
        pass

    def copy_directory(): # копирование директорий
        pass

    def move_directory(): # перемещение дерикторий
        pass

    def list_directory(): # список директорий
        pass
#Files
    def create_file(self, path: str, content: str, owner: str = "root", perms: int = 644) -> bool: # создание файлов
        if not self.selinux.check_access(path, "write", self.current_user, self.current_role):
            return False

        parent_dir = os.path.dirname(path)
        if not parent_dir:
            parent_dir = "/"
        if not self.db.execute("SELECT path FROM files WHERE path = ? AND type = 'directory'", (parent_dir,)).fetchone():
            self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"No write permission for {parent_dir}")
        if not self._check_primisions(parent_dir, self.current_user, "write"):
            self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"Path already exists: {path}")
        if not self.db.execute("SELECT path FROM files WHERE path = ?", (path,)).fetchone():
            self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Path already exists: {path}")
        inode = self._create_inode()
        ctime = mtime = time.time()
        size = len(content.encode())
        self.db.execute("INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)", (path, inode, content, owner, perms, "file", size, ctime, mtime))
        self.db.commit()
        self._log_journal("create", path, f"Created file: {path}")
        self.logger.info(f"File created: {path}")
        return True

    def read_file(self, path: str) -> Optional[str]: # чтение файлов
        if not self.selinux.check_access(path, "read", self.current_user, self.current_role):
            return None
        cursor = self.db.execute("SELECT content, perms, owner FROM files WHERE path = ? AND type = 'file'", (path,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"File not found: {path}")
        content, perms, owner = result
        if not self._check_permission(path, self.current_user, "read"):
            self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No read permission: {path}")
        self._log_journal("read", path, f"Read file: {path}")
        self.logger.info(f"File read: {path}")
        return content

    def write_file(self, path: str, content: str) -> bool: # запись файлов
        
        pass

    def remove_file(): # удаление файлов
        pass

    def rename_file(): # переименование файлов
        pass

    def copy_file(): # копирование файлов
        pass

    def move_file(): # перемещение файлов
        pass

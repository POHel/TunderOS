#TuNderFileSystem
#created by SKATT
import sqlite3
import time
from pathlib import Path
from typing import List, Optional, Dict
import os
import sys
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from libs.logging import Logger
from libs.CrashHandler import CrashHandler, TunderCrash

BASE_DIR = Path(__file__).resolve().parent.parent.parent
     
class TNFS:
    def __init__(self, logger: Logger, crash_handler: CrashHandler, user_manager: 'UserManager', selinux: Optional['SELinux'] = None):
        from core.users import UserManager
        from security.SELinux import SELinux
        self.logger = logger
        self.crash_handler = crash_handler
        self.user_manager = user_manager
        self.selinux = selinux
        self.cache = {}
        self.db = sqlite3.connect(BASE_DIR / "data" / "tnfs.db", timeout=10)
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
                details TEXT,
                user TEXT
            )
        """)
        try:
            self.db.execute("ALTER TABLE journal ADD COLUMN user TEXT")
            self.logger.info("Added 'user' column to journal table")
        except sqlite3.OperationalError:
            pass
        self.current_user = "user"
        self.current_role = "user"
        self.init_default_structure()
        self.logger.info("Tunder File System initialized")

    def init_default_structure(self):
        """Создает начальную структуру файловой системы."""
        defaults = [
            ("/", "", "root", 0o755, "directory", 0),
            ("/home", "", "root", 0o755, "directory", 0),
            ("/etc", "", "root", 0o755, "directory", 0),
            ("/bin", "", "root", 0o755, "directory", 0),
            ("/var", "", "root", 0o755, "directory", 0),
            ("/tmp", "", "root", 0o777, "directory", 0)
        ]
        for path, content, owner, perms, type_, size in defaults:
            if not self.db.execute("SELECT path FROM files WHERE path = ?", (path,)).fetchone():
                inode = self._create_inode()
                ctime = mtime = time.time()
                self.db.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (path, inode, content, owner, perms, type_, size, ctime, mtime)
                )
                self._log_journal("create", path, f"Created {type_}: {path}")
        self.db.commit()
        self.logger.info("Default TNFS structure committed to database")
        cursor = self.db.execute("SELECT path, perms FROM files WHERE path = '/'")
        result = cursor.fetchone()
        if result:
            self.logger.info(f"Confirmed / exists in database with perms={oct(result[1])}")
        else:
            self.logger.error("Failed to confirm / in database")
        self.logger.info("Default TNFS structure initialized")

    def _create_inode(self) -> int:
        """Создает новый инод."""
        with self.db:
            cursor = self.db.execute("INSERT INTO inodes (ref_count) VALUES (1)")
            inode = cursor.lastrowid
            self.logger.info(f"Created inode: {inode}")
            return inode

    def _check_permissions(self, path: str, user: str, operation: str) -> bool:
        """Проверяет разрешения на основе chmod."""
        with self.db:
            cursor = self.db.execute("SELECT owner, perms FROM files WHERE path = ?", (path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Path not found: {path}")
            owner, perms = result
            self.logger.info(f"Checking permissions: path={path}, user={user}, operation={operation}, owner={owner}, perms={oct(perms)}")
            # Права в восьмеричной системе: owner (u), group (g), others (o)
            owner_perms = (perms >> 6) & 0o7  # Права владельца
            other_perms = perms & 0o7  # Права для остальных
            operation_bits = {"read": 0o4, "write": 0o2, "execute": 0o1}
            required_bit = operation_bits.get(operation)
            if not required_bit:
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Invalid operation: {operation}")
            if user == owner or user == "root":
                self.logger.info(f"User is owner or root, checking owner perms: {oct(owner_perms)} & {oct(required_bit)}")
                return (owner_perms & required_bit) == required_bit
            self.logger.info(f"User is not owner, checking other perms: {oct(other_perms)} & {oct(required_bit)}")
            return operation in ["read", "execute"] and (other_perms & required_bit) == required_bit

    def _log_journal(self, operation: str, path: str, details: str):
        """Логирует операцию в журнал."""
        with self.db:
            self.db.execute(
                "INSERT INTO journal (operation, path, timestamp, details, user) VALUES (?, ?, ?, ?, ?)",
                (operation, path, time.time(), details, self.current_user)
            )

    def create_directory(self, path: str, owner: str = "root", perms: int = 0o755) -> bool:
        """Создает директорию."""
        self.logger.info(f"Creating directory: {path}")
        if not self.selinux.check_access(path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {path} for {self.current_user} ({self.current_role})")
        parent_dir = os.path.dirname(path) or "/"
        with self.db:
            cursor = self.db.execute("SELECT path FROM files WHERE path = ? AND type = 'directory'", (parent_dir,))
            if not cursor.fetchone():
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Parent directory not found: {parent_dir}")
            if not self._check_permissions(parent_dir, self.current_user, "write"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No write permission for {parent_dir}")
            if self.db.execute("SELECT path FROM files WHERE path = ?", (path,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path already exists: {path}")
            inode = self._create_inode()
            ctime = mtime = time.time()
            self.db.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (path, inode, "", owner, perms, "directory", 0, ctime, mtime)
            )
            self._log_journal("create", path, f"Created directory: {path}")
            self.logger.info(f"Directory created: {path}")
        return True

    def remove(self, path: str) -> bool:
        """Удаляет файл или директорию."""
        self.logger.info(f"Removing path: {path}")
        if not self.selinux.check_access(path, "delete", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied delete on {path} for {self.current_user} ({self.current_role})")
        with self.db:
            cursor = self.db.execute("SELECT type, inode, perms, owner FROM files WHERE path = ?", (path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Path not found: {path}")
            type_, inode, perms, owner = result
            if not self._check_permissions(path, self.current_user, "write"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No write permission: {path}")
            if type_ == "directory":
                if self.db.execute("SELECT path FROM files WHERE path LIKE ? AND path != ?", (f"{path}/%", path)).fetchone():
                    self.crash_handler.raise_crash("FS", "0xDNE0ERR", f"Directory not empty: {path}")
            self.db.execute("DELETE FROM files WHERE path = ?", (path,))
            self.db.execute("UPDATE inodes SET ref_count = ref_count - 1 WHERE inode = ?", (inode,))
            if path in self.cache:
                del self.cache[path]
            self._log_journal("delete", path, f"Deleted {type_}: {path}")
            self.logger.info(f"{type_.capitalize()} deleted: {path}")
        return True

    def rename_directory(self, old_path: str, new_path: str) -> bool:
        """Переименовывает директорию."""
        self.logger.info(f"Renaming directory: {old_path} to {new_path}")
        if not self.selinux.check_access(old_path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {old_path} for {self.current_user} ({self.current_role})")
        if not self.selinux.check_access(new_path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {new_path} for {self.current_user} ({self.current_role})")
        with self.db:
            cursor = self.db.execute("SELECT type, perms, owner FROM files WHERE path = ?", (old_path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Directory not found: {old_path}")
            type_, perms, owner = result
            if type_ != "directory":
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path is not a directory: {old_path}")
            if not self._check_permissions(old_path, self.current_user, "write"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No write permission: {old_path}")
            parent_dir = os.path.dirname(new_path) or "/"
            if not self.db.execute("SELECT path FROM files WHERE path = ? AND type = 'directory'", (parent_dir,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Parent directory not found: {parent_dir}")
            if self.db.execute("SELECT path FROM files WHERE path = ?", (new_path,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path already exists: {new_path}")
            self.db.execute("UPDATE files SET path = ? WHERE path = ?", (new_path, old_path))
            if old_path in self.cache:
                self.cache[new_path] = self.cache.pop(old_path)
            self._log_journal("rename", old_path, f"Renamed directory {old_path} to {new_path}")
            self.logger.info(f"Directory renamed: {old_path} to {new_path}")
        return True

    def copy_directory(self, src_path: str, dst_path: str) -> bool:
        """Копирует директорию и ее содержимое."""
        self.logger.info(f"Copying directory: {src_path} to {dst_path}")
        if not self.selinux.check_access(src_path, "read", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied read on {src_path} for {self.current_user} ({self.current_role})")
        if not self.selinux.check_access(dst_path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {dst_path} for {self.current_user} ({self.current_role})")
        with self.db:
            cursor = self.db.execute("SELECT type, perms, owner FROM files WHERE path = ?", (src_path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Directory not found: {src_path}")
            type_, perms, owner = result
            if type_ != "directory":
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path is not a directory: {src_path}")
            if not self._check_permissions(src_path, self.current_user, "read"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No read permission: {src_path}")
            parent_dir = os.path.dirname(dst_path) or "/"
            if not self.db.execute("SELECT path FROM files WHERE path = ? AND type = 'directory'", (parent_dir,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Parent directory not found: {parent_dir}")
            if self.db.execute("SELECT path FROM files WHERE path = ?", (dst_path,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path already exists: {dst_path}")
            inode = self._create_inode()
            ctime = mtime = time.time()
            self.db.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (dst_path, inode, "", owner, perms, "directory", 0, ctime, mtime)
            )
            cursor = self.db.execute("SELECT path, inode, content, owner, perms, type, size, ctime, mtime FROM files WHERE path LIKE ? AND path != ?", (f"{src_path}/%", src_path))
            for row in cursor.fetchall():
                old_subpath = row[0]
                new_subpath = dst_path + old_subpath[len(src_path):]
                new_inode = self._create_inode()
                self.db.execute(
                    "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (new_subpath, new_inode, row[2], row[3], row[4], row[5], row[6], row[7], row[8])
                )
            self._log_journal("copy", src_path, f"Copied directory {src_path} to {dst_path}")
            self.logger.info(f"Directory copied: {src_path} to {dst_path}")
        return True

    def move_directory(self, src_path: str, dst_path: str) -> bool:
        """Перемещает директорию."""
        if self.rename_directory(src_path, dst_path):
            self._log_journal("move", src_path, f"Moved directory {src_path} to {dst_path}")
            self.logger.info(f"Directory moved: {src_path} to {dst_path}")
            return True
        return False

    def list_directory(self, path: str) -> List[str]:
        """Возвращает список содержимого директории."""
        self.logger.info(f"Listing directory: {path}")
        if not self.selinux.check_access(path, "read", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied read on {path} for {self.current_user} ({self.current_role})")
        with self.db:
            cursor = self.db.execute("SELECT type FROM files WHERE path = ?", (path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Directory not found: {path}")
            if result[0] != "directory":
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path is not a directory: {path}")
            if not self._check_permissions(path, self.current_user, "read"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No read permission: {path}")
            # Убедимся, что путь заканчивается на / для корректного LIKE
            normalized_path = path.rstrip("/") + "/"
            cursor = self.db.execute(
                "SELECT path FROM files WHERE path LIKE ? AND path != ? AND path NOT LIKE ?",
                (f"{normalized_path}%", path, f"{normalized_path}%/%")
            )
            files = [os.path.basename(row[0]) for row in cursor.fetchall()]
            self._log_journal("list", path, f"Listed directory: {path}")
            self.logger.info(f"Directory listed: {path}")
            return files

    def create_file(self, path: str, content: str, owner: str = "root", perms: int = 0o644) -> bool:
        """Создает файл."""
        self.logger.info(f"Attempting to create file: {path}")
        self.logger.info(f"Current user: {self.current_user}, role: {self.current_role}, session_id: {self.user_manager.current_session_id}")
        if not path or not isinstance(path, str):
            self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Invalid path: {path}")
        try:
            if not self.selinux.check_access(path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
                self.logger.info(f"SELinux denied write access to {path}")
                self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {path} for {self.current_user} ({self.current_role})")
        except TunderCrash as e:
            self.logger.error(f"SELinux check failed: {str(e)}")
            raise
        parent_dir = os.path.dirname(path) or "/"
        self.logger.info(f"Checking parent directory: {parent_dir}")
        with self.db:
            cursor = self.db.execute("SELECT path FROM files WHERE path = ? AND type = 'directory'", (parent_dir,))
            if not cursor.fetchone():
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Parent directory not found: {parent_dir}")
            self.logger.info(f"Parent directory {parent_dir} exists")
            if not self._check_permissions(parent_dir, self.current_user, "write"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No write permission for {parent_dir}")
            self.logger.info(f"Write permission granted for {parent_dir}")
            if self.db.execute("SELECT path FROM files WHERE path = ?", (path,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path already exists: {path}")
            inode = self._create_inode()
            ctime = mtime = time.time()
            size = len(content.encode())
            self.db.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (path, inode, content, owner, perms, "file", size, ctime, mtime)
            )
            self.db.commit()
            self.logger.info(f"Inserted file into database: {path}, inode: {inode}, size: {size}")
            cursor = self.db.execute("SELECT path FROM files WHERE path = ?", (path,))
            if cursor.fetchone():
                self.logger.info(f"Confirmed file exists in database: {path}")
            else:
                self.logger.error(f"Failed to confirm file creation: {path}")
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Failed to create file: {path}")
            self._log_journal("create", path, f"Created file: {path}")
            self.logger.info(f"File created: {path}")
        return True

    def read_file(self, path: str) -> Optional[str]:
        """Читает содержимое файла."""
        self.logger.info(f"Reading file: {path}")
        if path in self.cache:
            if not self._check_permissions(path, self.current_user, "read"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No read permission: {path}")
            if not self.selinux.check_access(path, "read", self.current_user, self.current_role, self.user_manager.current_session_id):
                self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied read on {path} for {self.current_user} ({self.current_role})")
            return self.cache[path]
        with self.db:
            cursor = self.db.execute("SELECT content, perms, owner, type FROM files WHERE path = ?", (path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"File not found: {path}")
            content, perms, owner, type_ = result
            if type_ != "file":
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path is not a file: {path}")
            if not self._check_permissions(path, self.current_user, "read"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No read permission: {path}")
            if not self.selinux.check_access(path, "read", self.current_user, self.current_role, self.user_manager.current_session_id):
                self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied read on {path} for {self.current_user} ({self.current_role})")
            self.cache[path] = content
            self._log_journal("read", path, f"Read file: {path}")
            self.logger.info(f"File read: {path}")
            return content

    def write_file(self, path: str, content: str) -> bool:
        """Пишет в файл."""
        self.logger.info(f"Writing to file: {path}")
        if not self.selinux.check_access(path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {path} for {self.current_user} ({self.current_role})")
        with self.db:
            cursor = self.db.execute("SELECT perms, owner, type FROM files WHERE path = ?", (path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"File not found: {path}")
            perms, owner, type_ = result
            if type_ != "file":
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path is not a file: {path}")
            if not self._check_permissions(path, self.current_user, "write"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No write permission: {path}")
            mtime = time.time()
            size = len(content.encode())
            self.db.execute("UPDATE files SET content = ?, size = ?, mtime = ? WHERE path = ?", (content, size, mtime, path))
            self.cache[path] = content
            self._log_journal("write", path, f"Wrote to file: {path}")
            self.logger.info(f"File written: {path}")
        return True

    def rename_file(self, old_path: str, new_path: str) -> bool:
        """Переименовывает файл."""
        self.logger.info(f"Renaming file: {old_path} to {new_path}")
        if not self.selinux.check_access(old_path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {old_path} for {self.current_user} ({self.current_role})")
        if not self.selinux.check_access(new_path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {new_path} for {self.current_user} ({self.current_role})")
        with self.db:
            cursor = self.db.execute("SELECT type, perms, owner FROM files WHERE path = ?", (old_path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"File not found: {old_path}")
            type_, perms, owner = result
            if type_ != "file":
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path is not a file: {old_path}")
            if not self._check_permissions(old_path, self.current_user, "write"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No write permission: {old_path}")
            parent_dir = os.path.dirname(new_path) or "/"
            if not self.db.execute("SELECT path FROM files WHERE path = ? AND type = 'directory'", (parent_dir,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Parent directory not found: {parent_dir}")
            if self.db.execute("SELECT path FROM files WHERE path = ?", (new_path,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path already exists: {new_path}")
            self.db.execute("UPDATE files SET path = ? WHERE path = ?", (new_path, old_path))
            if old_path in self.cache:
                self.cache[new_path] = self.cache.pop(old_path)
            self._log_journal("rename", old_path, f"Renamed file {old_path} to {new_path}")
            self.logger.info(f"File renamed: {old_path} to {new_path}")
        return True

    def copy_file(self, src_path: str, dst_path: str) -> bool:
        """Копирует файл."""
        self.logger.info(f"Copying file: {src_path} to {dst_path}")
        if not self.selinux.check_access(src_path, "read", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied read on {src_path} for {self.current_user} ({self.current_role})")
        if not self.selinux.check_access(dst_path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {dst_path} for {self.current_user} ({self.current_role})")
        with self.db:
            cursor = self.db.execute("SELECT content, owner, perms, type FROM files WHERE path = ?", (src_path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"File not found: {src_path}")
            content, owner, perms, type_ = result
            if type_ != "file":
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path is not a file: {src_path}")
            if not self._check_permissions(src_path, self.current_user, "read"):
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No read permission: {src_path}")
            parent_dir = os.path.dirname(dst_path) or "/"
            if not self.db.execute("SELECT path FROM files WHERE path = ? AND type = 'directory'", (parent_dir,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Parent directory not found: {parent_dir}")
            if self.db.execute("SELECT path FROM files WHERE path = ?", (dst_path,)).fetchone():
                self.crash_handler.raise_crash("FS", "0xV0E0ERR", f"Path already exists: {dst_path}")
            inode = self._create_inode()
            ctime = mtime = time.time()
            size = len(content.encode())
            self.db.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (dst_path, inode, content, owner, perms, "file", size, ctime, mtime)
            )
            self.cache[dst_path] = content
            self._log_journal("copy", src_path, f"Copied file {src_path} to {dst_path}")
            self.logger.info(f"File copied: {src_path} to {dst_path}")
        return True

    def move_file(self, src_path: str, dst_path: str) -> bool:
        """Перемещает файл."""
        if self.rename_file(src_path, dst_path):
            self._log_journal("move", src_path, f"Moved file {src_path} to {dst_path}")
            self.logger.info(f"File moved: {src_path} to {dst_path}")
            return True
        return False

    def chmod(self, path: str, perms: int) -> bool:
        """Изменяет права доступа."""
        self.logger.info(f"Changing permissions: {path} to {oct(perms)}")
        if not self.selinux.check_access(path, "write", self.current_user, self.current_role, self.user_manager.current_session_id):
            self.crash_handler.raise_crash("FS", "0xSAD0ERR", f"SELinux: Denied write on {path} for {self.current_user} ({self.current_role})")
        with self.db:
            cursor = self.db.execute("SELECT owner, type FROM files WHERE path = ?", (path,))
            result = cursor.fetchone()
            if not result:
                self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Path not found: {path}")
            owner, type_ = result
            if self.current_user != owner and self.current_user != "root":
                self.crash_handler.raise_crash("FS", "0xPDN0ERR", f"No permission to change perms: {path}")
            self.db.execute("UPDATE files SET perms = ? WHERE path = ?", (perms, path))
            self._log_journal("chmod", path, f"Changed permissions to {oct(perms)}: {path}")
            self.logger.info(f"Permissions changed: {path} to {oct(perms)}")
        return True
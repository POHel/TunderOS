#Kernel TunderOS
#created by SKATT
from pathlib import Path
from typing import List, Dict
import os
import sys
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from TNFS.TNFS import TNFS
from core.users import UserManager
from security.SELinux import SELinux
from libs.logging import Logger
from libs.CrashHandler import CrashHandler

class Kernel:
    def __init__(self, logger: Logger, crash_handler: CrashHandler, user_manager: UserManager, tnfs: TNFS, selinux: SELinux):
        self.logger = Logger("kernel")
        self.crash_handler = CrashHandler(self.logger, self)
        self.user_manager = UserManager(self.logger, self.crash_handler)
        self.tnfs = TNFS(self.logger, self.crash_handler, self.user_manager, None)
        self.selinux = SELinux(self.logger, self.crash_handler, self.tnfs)
        self.tnfs.selinux = self.selinux
        self.user_manager.tnfs = self.tnfs
        self.processes = {}
        self.memory = {}
        self.next_pid = 1
        self.running = True
        self.logger.info("Kernel initialized")

    def login(self, username: str, password: str) -> bool:
        return self.user_manager.login(username, password)

    def logout(self, session_id: int) -> bool:
        return self.user_manager.logout(session_id)

    def add_user(self, username: str, password: str, role: str = "user") -> bool:
        return self.user_manager.add_user(username, password, role)

    def delete_user(self, username: str) -> bool:
        return self.user_manager.delete_user(username)

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        return self.user_manager.change_password(username, old_password, new_password)

    def get_active_sessions(self) -> List[Dict]:
        return self.user_manager.get_active_sessions()

    def get_session_info(self, session_id: int) -> Dict:
        return self.user_manager.get_session_info(session_id)

    def list_dir(self, path: str) -> List[str]:
        return self.tnfs.list_directory(path)

    def read_file(self, path: str) -> str:
        return self.tnfs.read_file(path)

    def create_file(self, path: str, content: str):
        self.tnfs.create_file(path, content)

    def create_directory(self, path: str):
        self.tnfs.create_directory(path)

    def remove(self, path: str):
        self.tnfs.remove(path)

    def chmod(self, path: str, perms: int):
        self.tnfs.chmod(path, perms)

    def rename(self, old_path: str, new_path: str):
        cursor = self.tnfs.db.execute("SELECT type FROM files WHERE path = ?", (old_path,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Path not found: {old_path}")
        if result[0] == "directory":
            self.tnfs.rename_directory(old_path, new_path)
        else:
            self.tnfs.rename_file(old_path, new_path)

    def copy(self, src_path: str, dst_path: str):
        cursor = self.tnfs.db.execute("SELECT type FROM files WHERE path = ?", (src_path,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Path not found: {src_path}")
        if result[0] == "directory":
            self.tnfs.copy_directory(src_path, dst_path)
        else:
            self.tnfs.copy_file(src_path, dst_path)

    def move(self, src_path: str, dst_path: str):
        cursor = self.tnfs.db.execute("SELECT type FROM files WHERE path = ?", (src_path,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Path not found: {src_path}")
        if result[0] == "directory":
            self.tnfs.move_directory(src_path, dst_path)
        else:
            self.tnfs.move_file(src_path, dst_path)
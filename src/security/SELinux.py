#SELinux
#created by Antarctica
import json
import sqlite3
import time
from pathlib import Path
from typing import List, Optional, Dict
import sys
import os
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from libs.logging import Logger
from libs.CrashHandler import CrashHandler, TunderCrash
from TNFS.TNFS import TNFS

BASE_DIR = Path(__file__).resolve().parent.parent.parent
SELinux_CONFIG = BASE_DIR / "data" / "selinux.json"
SELinux_DB = BASE_DIR / "data" / "selinux.db"

class SELinux:
    def __init__(self, logger: Logger, crash_handler: CrashHandler, tnfs: TNFS):
        self.logger = logger
        self.crash_handler = crash_handler
        self.tnfs = tnfs
        self.db = sqlite3.connect(BASE_DIR / "data" / "selinux.db", timeout=10)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS selinux_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id INTEGER,
                username TEXT,
                role TEXT,
                path TEXT,
                operation TEXT,
                result TEXT CHECK(result IN ('granted', 'denied')),
                timestamp REAL,
                mode TEXT CHECK(mode IN ('enforcing', 'permissive'))
            )
        """)
        self.policies = {
            "mode": "enforcing",
            "rules": {
                "/": {"read": ["root", "user"], "write": ["root", "user"], "execute": ["root", "user"], "delete": ["root", "user"], "type": "directory"},
                "/home": {"read": ["root", "user"], "write": ["root", "user"], "execute": ["root", "user"], "delete": ["root"], "type": "directory"},
                "/etc": {"read": ["root"], "write": ["root"], "execute": ["root"], "delete": ["root"], "type": "directory"},
                "/bin": {"read": ["root", "user", "guest"], "write": ["root"], "execute": ["root", "user", "guest"], "delete": ["root"], "type": "directory"},
                "/var": {"read": ["root"], "write": ["root"], "execute": ["root"], "delete": ["root"], "type": "directory"},
                "/tmp": {"read": ["root", "user", "guest"], "write": ["root", "user", "guest"], "execute": ["root", "user", "guest"], "delete": ["root", "user", "guest"], "type": "directory"}
            }
        }
        try:
            with open(BASE_DIR / "data" / "selinux_policies.json", "r") as f:
                self.policies = json.load(f)
        except FileNotFoundError:
            with open(BASE_DIR / "data" / "selinux_policies.json", "w") as f:
                json.dump(self.policies, f, indent=2)
        self.mode = self.policies["mode"]
        self.db.commit()
        self.logger.info("Loaded SELinux policies")
        self.logger.debug(f"Initial policies: {self.policies}")
        self.logger.info(f"SELinux initialized in {self.mode} mode")

    def set_mode(self, mode: str):
        """Устанавливает режим SELinux (enforcing или permissive)."""
        if mode not in ["enforcing", "permissive"]:
            self.crash_handler.raise_crash("SELINUX", "0xSIM0ERR", f"Invalid SELinux mode: {mode}")
        self.mode = mode
        self.policies["mode"] = mode
        with open(BASE_DIR / "data" / "selinux_policies.json", "w") as f:
            json.dump(self.policies, f, indent=2)
        self.db.commit()
        self.logger.info(f"SELinux mode set to {mode}")

    def check_access(self, path: str, operation: str, username: str, role: str, session_id: int) -> bool:
        """Проверяет доступ к пути на основе SELinux-политик."""
        self.logger.debug(f"Checking SELinux access: path={path}, operation={operation}, username={username}, role={role}, session_id={session_id}")
        
        if operation != "write" and self.tnfs:
            with self.tnfs.db:
                cursor = self.tnfs.db.execute("SELECT path, type FROM files WHERE path = ?", (path,))
                if not cursor.fetchone():
                    self.crash_handler.raise_crash("FS", "0xFNF0ERR", f"Path not found: {path}")

        result = False
        parent_dir = os.path.dirname(path) or "/"

        if path in self.policies["rules"]:
            if operation in self.policies["rules"][path] and role in self.policies["rules"][path][operation]:
                result = True
            elif role == "root":
                result = True
        else:
            if parent_dir in self.policies["rules"]:
                if operation in self.policies["rules"][parent_dir] and role in self.policies["rules"][parent_dir][operation]:
                    result = True
                elif role == "root":
                    result = True

        self.logger.debug(
            f"SELinux policy check for {path}/{operation}: result={result}, "
            f"policies={self.policies['rules'].get(path, self.policies['rules'].get(parent_dir, {}))}"
        )

        if self.mode == "permissive":
            result = True

        with self.db:
            self.db.execute(
                "INSERT INTO selinux_audit (session_id, username, role, path, operation, result, timestamp, mode) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (session_id, username, role, path, operation, "granted" if result else "denied", time.time(), self.mode)
            )

        if not result and self.mode == "enforcing":
            self.crash_handler.raise_crash("SELINUX", "0xSAD0ERR", f"Denied {operation} on {path} for {username} ({role})")

        self.logger.info(f"SELinux access {'granted' if result else 'denied'}: {operation} on {path} for {username} ({role})")
        return result

    def add_rule(self, path: str, operation: str, roles: List[str], type_: str):
        """Добавляет новое правило SELinux."""
        self.logger.debug(f"Adding SELinux rule: path={path}, operation={operation}, roles={roles}, type={type_}")
        if self.tnfs:
            with self.tnfs.db:
                cursor = self.tnfs.db.execute("SELECT type FROM files WHERE path = ?", (path,))
                result = cursor.fetchone()
                if not result and path not in self.policies["rules"]:
                    self.logger.debug(f"Path {path} not found in TNFS, allowing rule addition for future file")
        if path not in self.policies["rules"]:
            self.policies["rules"][path] = {"read": [], "write": [], "execute": [], "delete": [], "type": type_}
        if operation not in self.policies["rules"][path]:
            self.policies["rules"][path][operation] = []
        self.policies["rules"][path][operation].extend(roles)
        self.policies["rules"][path][operation] = list(set(self.policies["rules"][path][operation]))
        with open(BASE_DIR / "data" / "selinux_policies.json", "w") as f:
            json.dump(self.policies, f, indent=2)
        self.db.commit()
        self.logger.debug(f"Updated policies: {self.policies['rules'][path]}")
        self.logger.info(f"Added SELinux rule: {operation} on {path} for roles {roles}")

    def remove_rule(self, path: str, operation: str, roles: List[str]):
        """Удаляет правило SELinux."""
        self.logger.debug(f"Removing SELinux rule: path={path}, operation={operation}, roles={roles}")
        if path not in self.policies["rules"] or operation not in self.policies["rules"][path]:
            self.crash_handler.raise_crash("SELINUX", "0xSRN0ERR", f"No rule found for {operation} on {path}")
        self.policies["rules"][path][operation] = [r for r in self.policies["rules"][path][operation] if r not in roles]
        if not self.policies["rules"][path][operation]:
            del self.policies["rules"][path][operation]
        if not self.policies["rules"][path]:
            del self.policies["rules"][path]
        with open(BASE_DIR / "data" / "selinux_policies.json", "w") as f:
            json.dump(self.policies, f, indent=2)
        self.db.commit()
        self.logger.info(f"Removed SELinux rule: {operation} on {path} for roles {roles}")

    def list_rules(self) -> Dict:
        """Возвращает текущие правила SELinux."""
        return self.policies["rules"]

    def reset_policies(self):
        """Сбрасывает политики SELinux к значениям по умолчанию."""
        self.policies = {
            "mode": "permissive",
            "rules": {
                "/": {"read": ["root"], "write": ["root"], "execute": ["root"], "delete": ["root"], "type": "directory"},
                "/home": {"read": ["root", "user"], "write": ["root", "user"], "execute": ["root", "user"], "delete": ["root"], "type": "directory"},
                "/etc": {"read": ["root"], "write": ["root"], "execute": ["root"], "delete": ["root"], "type": "directory"},
                "/bin": {"read": ["root", "user", "guest"], "write": ["root"], "execute": ["root", "user", "guest"], "delete": ["root"], "type": "directory"},
                "/var": {"read": ["root"], "write": ["root"], "execute": ["root"], "delete": ["root"], "type": "directory"},
                "/tmp": {"read": ["root", "user", "guest"], "write": ["root", "user", "guest"], "execute": ["root", "user", "guest"], "delete": ["root", "user", "guest"], "type": "directory"}
            }
        }
        self.mode = self.policies["mode"]
        with open(BASE_DIR / "data" / "selinux_policies.json", "w") as f:
            json.dump(self.policies, f, indent=2)
        self.db.commit()
        self.logger.info("SELinux policies reset to default")
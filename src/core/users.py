#UserManager
#created by SKATT
import sqlite3
import time
from pathlib import Path
from typing import Optional, List, Dict
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import sys
ININ_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(ININ_DIR)
from libs.logging import Logger
from libs.CrashHandler import CrashHandler, TunderCrash
from TNFS.TNFS import TNFS
BASE_DIR = Path(__file__).resolve().parent.parent.parent

class UserManager:
    def __init__(self, logger: Logger, crash_handler: CrashHandler):
        self.logger = logger
        self.crash_handler = crash_handler
        self.tnfs = None
        self.db = sqlite3.connect(BASE_DIR / "data" / "users.db", timeout=10)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT,
                role TEXT
            )
        """)
        self.db.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT,
                login_time REAL,
                FOREIGN KEY(username) REFERENCES users(username)
            )
        """)
        self.current_session_id = None
        self.init_default_users()
        self.logger.info("UserManager initialized")

    def init_default_users(self):
        defaults = [
            ("root", "root", "root"),
            ("guest", "guest", "guest"),
            ("user", "user", "user")
        ]
        for username, password, role in defaults:
            if not self.db.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone():
                self.db.execute("INSERT INTO users VALUES (?, ?, ?)", (username, password, role))
        self.db.commit()

    def login(self, username: str, password: str) -> bool:
        cursor = self.db.execute("SELECT password, role FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result or result[0] != password:
            self.crash_handler.raise_crash("USER", "0xUAF0ERR", f"Authentication failed for {username}")
        login_time = time.time()
        cursor = self.db.execute("INSERT INTO sessions (username, login_time) VALUES (?, ?)", (username, login_time))
        self.current_session_id = cursor.lastrowid
        self.db.commit()
        if self.tnfs:
            self.tnfs.current_user = username
            self.tnfs.current_role = result[1]
        self.logger.info(f"User {username} logged in (session {self.current_session_id})")
        return True

    def logout(self, session_id: int) -> bool:
        if not self.db.execute("SELECT session_id FROM sessions WHERE session_id = ?", (session_id,)).fetchone():
            self.crash_handler.raise_crash("USER", "0xSNF0ERR", f"Session {session_id} not found")
        self.db.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        self.db.commit()
        if session_id == self.current_session_id:
            self.current_session_id = None
            if self.tnfs:
                self.tnfs.current_user = "root"
                self.tnfs.current_role = "root"
        self.logger.info(f"Session {session_id} logged out")
        return True

    def add_user(self, username: str, password: str, role: str = "user") -> bool:
        if self.db.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone():
            self.crash_handler.raise_crash("USER", "0xUAE0ERR", f"User {username} already exists")
        self.db.execute("INSERT INTO users VALUES (?, ?, ?)", (username, password, role))
        self.db.commit()
        self.logger.info(f"User {username} added with role {role}")
        return True

    def delete_user(self, username: str) -> bool:
        if not self.db.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone():
            self.crash_handler.raise_crash("USER", "0xUNF0ERR", f"User {username} not found")
        self.db.execute("DELETE FROM users WHERE username = ?", (username,))
        self.db.execute("DELETE FROM sessions WHERE username = ?", (username,))
        self.db.commit()
        self.logger.info(f"User {username} deleted")
        return True

    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        cursor = self.db.execute("SELECT password FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("USER", "0xUNF0ERR", f"User {username} not found")
        if result[0] != old_password:
            self.crash_handler.raise_crash("USER", "0xUAF0ERR", f"Invalid old password for {username}")
        self.db.execute("UPDATE users SET password = ? WHERE username = ?", (new_password, username))
        self.db.commit()
        self.logger.info(f"Password changed for {username}")
        return True
    
    def start_session(self, username: str) -> int:
        """Создаёт новую сессию для пользователя."""
        if not self.db.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone():
            self.crash_handler.raise_crash("SYSTEM", "0xFNF0ERR", f"User not found: {username}")
        
        cursor = self.db.execute(
            "INSERT INTO sessions (username, login_time, status) VALUES (?, ?, ?)",
            (username, time.time(), "active")
        )
        self.db.commit()
        session_id = cursor.lastrowid
        self.logger.info(f"Session started: {username} (session: {session_id})")
        return session_id

    def end_session(self, session_id: int) -> bool:
        """Завершает сессию."""
        cursor = self.db.execute("SELECT username FROM sessions WHERE session_id = ?", (session_id,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("SYSTEM", "0xFNF0ERR", f"Session not found: {session_id}")
        
        username, status = result
        if status == "closed":
            self.crash_handler.raise_crash("SYSTEM", "0xV0E0ERR", f"Session already closed: {session_id}")
        
        self.db.execute(
            "UPDATE sessions SET status = ?, logout_time = ? WHERE session_id = ?",
            ("closed", time.time(), session_id)
        )
        self.db.commit()
        if username == self.current_user and session_id == self.current_session_id:
            self.current_user = "root"
            self.current_role = "root"
            self.current_session_id = None
            if self.skfs:
                self.skfs.current_user = "root"
                self.skfs.current_role = "root"
        self.logger.info(f"Session ended: {username} (session: {session_id})")
        return True


    def get_active_sessions(self) -> List[Dict]:
        cursor = self.db.execute("SELECT session_id, username, login_time FROM sessions")
        return [{"session_id": r[0], "username": r[1], "login_time": r[2]} for r in cursor.fetchall()]

    def get_session_info(self, session_id: int) -> Dict:
        cursor = self.db.execute("SELECT session_id, username, login_time FROM sessions WHERE session_id = ?", (session_id,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("USER", "0xSNF0ERR", f"Session {session_id} not found")
        return {"session_id": result[0], "username": result[1], "login_time": result[2]}
    
    def get_user_info(self, username: str) -> Dict:
        """Возвращает информацию о пользователе."""
        cursor = self.db.execute("SELECT username, role, home_dir, uid, created_at FROM users WHERE username = ?", (username,))
        result = cursor.fetchone()
        if not result:
            self.crash_handler.raise_crash("SYSTEM", "0xFNF0ERR", f"User not found: {username}")
        
        return {
            "username": result[0],
            "role": result[1],
            "home_dir": result[2],
            "uid": result[3],
            "created_at": result[4]
        }
    
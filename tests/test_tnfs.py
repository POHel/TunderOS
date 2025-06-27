#test TNFS
#created by SKATT
import pytest
import sqlite3
import os
import sys
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR) 
from src.TNFS.TNFS import TNFS
from src.libs.logging import Logger
from src.libs.CrashHandler import CrashHandler, TunderCrash
from src.core.users import UserManager
from src.security.SELinux import SELinux

@pytest.fixture
def temp_db(tmp_path):
    """Создаёт временную базу данных для тестов."""
    db_path = tmp_path / "tnfs.db"
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("CREATE TABLE IF NOT EXISTS inodes (inode INTEGER PRIMARY KEY AUTOINCREMENT, ref_count INTEGER DEFAULT 1)")
    conn.execute("""
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
    conn.execute("""
        CREATE TABLE IF NOT EXISTS journal (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            operation TEXT,
            path TEXT,
            timestamp REAL,
            details TEXT,
            user TEXT
        )
    """)
    conn.commit()
    yield db_path
    conn.close()

@pytest.fixture
def selinux(temp_db):
    logger = Logger("test")
    crash_handler = CrashHandler(logger)
    user_manager = UserManager(logger, crash_handler)
    
    # Создаём TNFS с временным соединением
    tnfs = TNFS(logger, crash_handler, user_manager, None)

    # Заменяем подключение к БД на временную
    tnfs.db = sqlite3.connect(temp_db, timeout=10)

    # Заново создаём базовую структуру, но уже в temp_db
    tnfs.init_default_structure()
    tnfs.current_user = "root"
    tnfs.current_role = "root"

    # Создаём SELinux
    selinux = SELinux(logger, crash_handler, tnfs)
    tnfs.selinux = selinux
    user_manager.tnfs = tnfs

    yield selinux

    # Закрываем соединения после тестов
    selinux.db.close()
    tnfs.db.close()

def test_check_access_enforcing(selinux):
    selinux.set_mode("enforcing")
    selinux.tnfs.create_directory("/home", owner="root", perms=755)
    selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644)
    assert selinux.check_access("/home/test.txt", "read", "user", "user", session_id=1) == True
    with pytest.raises(TunderCrash, match="Denied write on /home/test.txt"):
        selinux.check_access("/home/test.txt", "write", "guest", "guest", session_id=1)

def test_check_access_permissive(selinux):
    selinux.set_mode("permissive")
    selinux.tnfs.create_directory("/home", owner="root", perms=755)
    selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644)
    assert selinux.check_access("/home/test.txt", "write", "guest", "guest", session_id=1) == True
    audit = selinux.db.execute("SELECT result, mode FROM selinux_audit WHERE operation = 'write'").fetchone()
    assert audit == ("granted", "permissive")

def test_set_mode_invalid(selinux):
    with pytest.raises(TunderCrash, match="Invalid SELinux mode"):
        selinux.set_mode("invalid")

def test_add_rule_with_type(selinux):
    selinux.tnfs.create_directory("/home", owner="root", perms=755)
    selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644)
    selinux.add_rule("/home/test.txt", "write", ["user"], "file")
    assert selinux.check_access("/home/test.txt", "write", "user", "user", session_id=1) == True
    assert selinux.policies["rules"]["/home/test.txt"]["type"] == "file"

def test_add_rule_invalid_type(selinux):
    selinux.tnfs.create_directory("/home", owner="root", perms=755)
    selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644)
    with pytest.raises(TunderCrash, match="Path /home/test.txt is not directory"):
        selinux.add_rule("/home/test.txt", "write", ["user"], "directory")

def test_remove_rule(selinux):
    selinux.add_rule("/home", "write", ["user"], "directory")
    selinux.remove_rule("/home", "write", ["user"])
    selinux.set_mode("enforcing")
    with pytest.raises(TunderCrash, match="Denied write on /home"):
        selinux.check_access("/home", "write", "user", "user", session_id=1)

def test_remove_nonexistent_rule(selinux):
    selinux.tnfs.create_directory("/home", owner="root", perms=755)
    selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644)
    with pytest.raises(TunderCrash, match="No rule found"):
        selinux.remove_rule("/home", "write", ["user"])

def test_reset_policies(selinux):
    selinux.tnfs.create_directory("/home", owner="root", perms=755)
    selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644)
    selinux.add_rule("/home/test.txt", "write", ["user"], "file")
    selinux.reset_policies()
    assert selinux.mode == "permissive"
    assert selinux.policies["rules"].get("/home/test.txt") is None

def test_check_nonexistent_path(selinux):
    with pytest.raises(TunderCrash, match="Path not found"):
        selinux.check_access("/nonexistent", "read", "user", "user", session_id=1)

def test_list_rules(selinux):
    rules = selinux.list_rules()
    assert "/home" in rules
    assert rules["/home"]["type"] == "directory"
    assert "user" in rules["/home"]["read"]

def test_audit_logging(selinux):
    selinux.tnfs.create_directory("/home", owner="root", perms=755)
    selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644)
    selinux.check_access("/home/test.txt", "read", "user", "user", session_id=1)
    audit = selinux.db.execute("SELECT session_id, username, operation, result FROM selinux_audit").fetchone()
    assert audit == (1, "user", "read", "granted")
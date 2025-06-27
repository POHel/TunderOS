import pytest
import sqlite3
import time
import os
import sys
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from src.libs.logging import Logger
from src.libs.CrashHandler import CrashHandler, TunderCrash
from src.TNFS.TNFS import TNFS
from src.security.SELinux import SELinux
from src.core.users import UserManager

@pytest.fixture
def temp_tnfs_db(tmp_path):
    """Создает временную базу данных TNFS для тестов."""
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
    defaults = [
        ("/", "", "root", 755, "directory", 0),
        ("/home", "", "root", 755, "directory", 0),
        ("/etc", "", "root", 755, "directory", 0),
        ("/bin", "", "root", 755, "directory", 0),
        ("/var", "", "root", 755, "directory", 0),
        ("/tmp", "", "root", 777, "directory", 0)
    ]
    for path, content, owner, perms, type_, size in defaults:
        if not conn.execute("SELECT path FROM files WHERE path = ?", (path,)).fetchone():
            cursor = conn.execute("INSERT INTO inodes (ref_count) VALUES (1)")
            inode = cursor.lastrowid
            ctime = mtime = time.time()
            conn.execute(
                "INSERT INTO files VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (path, inode, content, owner, perms, type_, size, ctime, mtime)
            )
    conn.commit()
    yield db_path
    conn.close()

@pytest.fixture
def temp_selinux_db(tmp_path):
    """Создает временную базу данных SELinux для тестов."""
    db_path = tmp_path / "selinux.db"
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("""
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
    conn.commit()
    yield db_path
    conn.close()

@pytest.fixture
def temp_users_db(tmp_path):
    """Создает временную базу данных пользователей для тестов."""
    db_path = tmp_path / "users.db"
    conn = sqlite3.connect(db_path, timeout=10)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password TEXT,
            role TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            session_id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT,
            login_time REAL,
            FOREIGN KEY(username) REFERENCES users(username)
        )
    """)
    defaults = [
        ("root", "root", "root"),
        ("guest", "guest", "guest"),
        ("user", "user", "user")
    ]
    for username, password, role in defaults:
        if not conn.execute("SELECT username FROM users WHERE username = ?", (username,)).fetchone():
            conn.execute("INSERT INTO users VALUES (?, ?, ?)", (username, password, role))
    conn.commit()
    yield db_path
    conn.close()

@pytest.fixture
def selinux(temp_tnfs_db, temp_selinux_db, temp_users_db):
    logger = Logger("test")
    crash_handler = CrashHandler(logger)
    user_manager = UserManager(logger, crash_handler)
    user_manager.db = sqlite3.connect(temp_users_db, timeout=10)
    tnfs = TNFS(logger, crash_handler, user_manager, None)
    tnfs.db = sqlite3.connect(temp_tnfs_db, timeout=10)
    user_manager.tnfs = tnfs
    selinux = SELinux(logger, crash_handler, tnfs)
    selinux.db = sqlite3.connect(temp_selinux_db, timeout=10)
    tnfs.selinux = selinux
    user_manager.login("user", "user")
    tnfs.current_user = "user"
    tnfs.current_role = "user"
    # Добавляем правило SELinux для /home/test.txt
    selinux.add_rule("/home/test.txt", "write", ["user"], "file")
    selinux.add_rule("/home/test.txt", "read", ["user"], "file")
    selinux.logger.debug(f"SELinux policies after setup: {selinux.policies}")
    yield selinux
    selinux.db.close()
    tnfs.db.close()
    user_manager.db.close()

def test_check_access_enforcing(selinux):
    selinux.set_mode("enforcing")
    try:
        assert selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644) == True
    except TunderCrash as e:
        pytest.fail(f"Failed to create file: {str(e)}")
    result = selinux.tnfs.db.execute("SELECT path FROM files WHERE path = ?", ("/home/test.txt",)).fetchone()
    assert result is not None, f"File /home/test.txt not found in database"
    assert selinux.check_access("/home/test.txt", "read", "user", "user", session_id=selinux.tnfs.user_manager.current_session_id) == True
    with pytest.raises(TunderCrash, match="Denied write on /home/test.txt"):
        selinux.check_access("/home/test.txt", "write", "guest", "guest", session_id=selinux.tnfs.user_manager.current_session_id)

def test_check_access_permissive(selinux):
    selinux.set_mode("permissive")
    try:
        assert selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644) == True
    except TunderCrash as e:
        pytest.fail(f"Failed to create file: {str(e)}")
    result = selinux.tnfs.db.execute("SELECT path FROM files WHERE path = ?", ("/home/test.txt",)).fetchone()
    assert result is not None, f"File /home/test.txt not found in database"
    assert selinux.check_access("/home/test.txt", "write", "guest", "guest", session_id=selinux.tnfs.user_manager.current_session_id) == True
    audit = selinux.db.execute("SELECT result, mode FROM selinux_audit WHERE operation = 'write'").fetchone()
    assert audit == ("granted", "permissive")

def test_set_mode_invalid(selinux):
    with pytest.raises(TunderCrash, match="Invalid SELinux mode"):
        selinux.set_mode("invalid")

def test_add_rule_with_type(selinux):
    try:
        assert selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644) == True
    except TunderCrash as e:
        pytest.fail(f"Failed to create file: {str(e)}")
    result = selinux.tnfs.db.execute("SELECT path FROM files WHERE path = ?", ("/home/test.txt",)).fetchone()
    assert result is not None, f"File /home/test.txt not found in database"
    selinux.add_rule("/home/test.txt", "write", ["user"], "file")
    assert selinux.check_access("/home/test.txt", "write", "user", "user", session_id=selinux.tnfs.user_manager.current_session_id) == True
    assert selinux.policies["rules"]["/home/test.txt"]["type"] == "file"

def test_add_rule_invalid_type(selinux):
    try:
        assert selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644) == True
    except TunderCrash as e:
        pytest.fail(f"Failed to create file: {str(e)}")
    result = selinux.tnfs.db.execute("SELECT path FROM files WHERE path = ?", ("/home/test.txt",)).fetchone()
    assert result is not None, f"File /home/test.txt not found in database"
    with pytest.raises(TunderCrash, match="Path /home/test.txt is not directory"):
        selinux.add_rule("/home/test.txt", "write", ["user"], "directory")

def test_remove_rule(selinux):
    try:
        assert selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644) == True
    except TunderCrash as e:
        pytest.fail(f"Failed to create file: {str(e)}")
    result = selinux.tnfs.db.execute("SELECT path FROM files WHERE path = ?", ("/home/test.txt",)).fetchone()
    assert result is not None, f"File /home/test.txt not found in database"
    selinux.add_rule("/home/test.txt", "write", ["user"], "file")
    selinux.remove_rule("/home/test.txt", "write", ["user"])
    selinux.set_mode("enforcing")
    with pytest.raises(TunderCrash, match="Denied write on /home/test.txt"):
        selinux.check_access("/home/test.txt", "write", "user", "user", session_id=selinux.tnfs.user_manager.current_session_id)

def test_remove_nonexistent_rule(selinux):
    with pytest.raises(TunderCrash, match="No rule found"):
        selinux.remove_rule("/nonexistent", "write", ["user"])

def test_reset_policies(selinux):
    try:
        assert selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644) == True
    except TunderCrash as e:
        pytest.fail(f"Failed to create file: {str(e)}")
    result = selinux.tnfs.db.execute("SELECT path FROM files WHERE path = ?", ("/home/test.txt",)).fetchone()
    assert result is not None, f"File /home/test.txt not found in database"
    selinux.add_rule("/home/test.txt", "write", ["user"], "file")
    selinux.reset_policies()
    assert selinux.mode == "permissive"
    assert selinux.policies["rules"].get("/home/test.txt") is None

def test_check_nonexistent_path(selinux):
    with pytest.raises(TunderCrash, match="Path not found"):
        selinux.check_access("/nonexistent", "read", "user", "user", session_id=selinux.tnfs.user_manager.current_session_id)

def test_list_rules(selinux):
    rules = selinux.list_rules()
    assert "/home" in rules
    assert rules["/home"]["type"] == "directory"
    assert "user" in rules["/home"]["read"]

def test_audit_logging(selinux):
    try:
        assert selinux.tnfs.create_file("/home/test.txt", "test", owner="root", perms=644) == True
    except TunderCrash as e:
        pytest.fail(f"Failed to create file: {str(e)}")
    result = selinux.tnfs.db.execute("SELECT path FROM files WHERE path = ?", ("/home/test.txt",)).fetchone()
    assert result is not None, f"File /home/test.txt not found in database"
    selinux.check_access("/home/test.txt", "read", "user", "user", session_id=selinux.tnfs.user_manager.current_session_id)
    audit = selinux.db.execute("SELECT session_id, username, operation, result FROM selinux_audit").fetchone()
    assert audit == (selinux.tnfs.user_manager.current_session_id, "user", "read", "granted")
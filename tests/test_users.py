import pytest
import os
import sys
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from src.core.users import UserManager
from src.libs.logging import Logger
from src.libs.CrashHandler import CrashHandler, TunderCrash

@pytest.fixture
def user_manager():
    logger = Logger("test")
    crash_handler = CrashHandler(logger)
    return UserManager(logger, crash_handler)

def test_add_user(user_manager):
    assert user_manager.add_user("testuser", "password", "user")
    user_info = user_manager.get_user_info("testuser")
    assert user_info["username"] == "testuser"
    assert user_info["role"] == "user"
    assert user_info["home_dir"] == "/home/testuser"

def test_add_existing_user(user_manager):
    user_manager.add_user("testuser", "password")
    with pytest.raises(TunderCrash, match="User already exists"):
        user_manager.add_user("testuser", "password")

def test_delete_user(user_manager):
    user_manager.add_user("testuser", "password")
    assert user_manager.delete_user("testuser")
    with pytest.raises(TunderCrash, match="User not found"):
        user_manager.get_user_info("testuser")

def test_delete_root(user_manager):
    with pytest.raises(TunderCrash, match="Cannot delete root user"):
        user_manager.delete_user("root")

def test_login(user_manager):
    user_manager.add_user("testuser", "password", "user")
    assert user_manager.login("testuser", "password")
    assert user_manager.current_user == "testuser"
    assert user_manager.current_role == "user"
    assert user_manager.current_session_id is not None

def test_login_failed(user_manager):
    with pytest.raises(TunderCrash, match="Authentication failed"):
        user_manager.login("testuser", "wrongpassword")

def test_change_password(user_manager):
    user_manager.add_user("testuser", "oldpassword")
    assert user_manager.change_password("testuser", "oldpassword", "newpassword")
    assert user_manager.login("testuser", "newpassword")

def test_session_management(user_manager):
    user_manager.add_user("testuser", "password")
    user_manager.login("testuser", "password")
    session_id = user_manager.current_session_id
    sessions = user_manager.get_active_sessions()
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == session_id
    assert sessions[0]["username"] == "testuser"
    assert user_manager.get_session_info(session_id)["status"] == "active"
    assert user_manager.end_session(session_id)
    assert user_manager.get_session_info(session_id)["status"] == "closed"
    assert user_manager.current_user == "root"
    assert user_manager.current_session_id is None

def test_end_nonexistent_session(user_manager):
    with pytest.raises(TunderCrash, match="Session not found"):
        user_manager.end_session(999)
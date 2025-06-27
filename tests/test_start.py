import pytest
import sys
from unittest.mock import patch
import os
import sys
INIT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(INIT_DIR)
from src.libs.logging import Logger
from src.libs.CrashHandler import CrashHandler
from src.core.TunKernel import Kernel
from src.shell.shell import Shell

def test_start_with_default_args():
    with patch.object(sys, "argv", ["start.py"]):
        from start import main
        with patch("src.shell.shell.Shell.run") as mock_shell_run:
            main()
            assert mock_shell_run.called
            logger = Logger("system")
            assert logger.last_message == "Shell initialized"

def test_start_with_debug():
    with patch.object(sys, "argv", ["start.py", "--debug"]):
        from start import main
        with patch("src.shell.shell.Shell.run") as mock_shell_run:
            main()
            logger = Logger("system", debug=True)
            assert logger.debug_enabled

def test_start_with_enforcing_mode():
    with patch.object(sys, "argv", ["start.py", "--mode", "enforcing"]):
        from start import main
        with patch("src.shell.shell.Shell.run") as mock_shell_run:
            main()
            kernel = Kernel()
            assert kernel.selinux.mode == "enforcing"

def test_start_with_invalid_mode():
    with patch.object(sys, "argv", ["start.py", "--mode", "invalid"]):
        from start import main
        with pytest.raises(SystemExit):
            main()
import os
import sys
import html
from pathlib import Path
from typing import List
from prompt_toolkit import PromptSession, print_formatted_text, HTML
from prompt_toolkit.key_binding import KeyBindings
from prompt_toolkit.keys import Keys
INIT_DIR = Path(__file__).resolve().parent
sys.path.append(str(INIT_DIR))
from core.TunKernel import Kernel
from src.libs.logging import Logger
from src.TNFS.TNFS import TNFS
from src.libs.CrashHandler import CrashHandler, TunderCrash

class Shell:
    COMMANDS = {
        "L.mktxt": "Create a new text file at the specified path. Usage: L.mktxt <path>",
        "L.mkdir": "Create a new directory at the specified path. Usage: L.mkdir <path>",
        "L.rm": "Remove a file or directory at the specified path. Usage: L.rm <path>",
        "L.chmod": "Change permissions of a file or directory. Usage: L.chmod <path> <perms> (e.g., 755)",
        "L.rename": "!!!DEV!!!Rename a file or directory. Usage: L.rename <old_path> <new_path>",
        "L.copy": "!!!DEV!!!Copy a file or directory. Usage: L.copy <src_path> <dst_path>",
        "L.move": "!!!DEV!!!Move a file or directory. Usage: L.move <src_path> <dst_path>",
        "cat": "!!!ERROR!!!Display the contents of a file. Usage: cat <path>",
        "ls": "!!!ERROR!!!List contents of a directory. Usage: ls [path] (defaults to /)",
        "adduser": "!!!ERROR!!!Add a new user. Usage: adduser <username> <password> [role] (default role: user)",
        "deluser": "!!!ERROR!!!Delete a user. Usage: deluser <username>",
        "passwd": "!!!ERROR!!!Change user password. Usage: passwd <username> <old_password> <new_password>",
        "login": "Log in as a user. Usage: login <username> <password>",
        "logout": "Log out the current user. Usage: logout",
        "who": "Show active user sessions. Usage: who",
        "whoami": "Show current user and session info. Usage: whoami",
        "SEL": "Set SELinux mode. Usage: SEL <enforcing/permissive>",
        "addrule": "!!!ERROR!!!Add an SELinux rule. Usage: addrule <path> <operation> <type> <subjects...>",
        "rmrule": "!!!ERROR!!!Remove an SELinux rule. Usage: rmrule <path> <operation> <subjects...>",
        "listrules": "List all SELinux rules. Usage: listrules",
        "resetSEL": "Reset SELinux policies to default. Usage: resetSEL",
        "L.warn": "Trigger a test warning. Usage: L.warn",
        "auditlogs": "!!!ERROR!!!Display SELinux audit logs. Usage: auditlogs",
        "exit": "Exit the shell. Usage: exit",
        "help": "Show this help message or details for a specific command. Usage: help [command]"
    }

    def __init__(self, kernel: Kernel, logger: Logger, crash_handler: CrashHandler, tnfs: TNFS):
        self.kernel = kernel
        self.logger = logger
        self.crash_handler = crash_handler
        self.tnfs = tnfs
        self.bindings = KeyBindings()
        self.bindings.add(Keys.ControlC)(self._handle_ctrl_c)
        self.kernel.login("root", "root")
        self.tnfs.current_user = "root"
        self.tnfs.current_role = "root"
        self.session = PromptSession(f"~{self.tnfs.current_user}--> ", key_bindings=self.bindings)
        self.logger.info("Shell initialized")

    def _handle_ctrl_c(self, event):
        print_formatted_text(HTML("<ansired>\r\nKeyboardInterrupt: Exiting shell</ansired>\r\n"))
        self.logger.info("Shell interrupted by Ctrl+C")
        sys.exit(0)

    def _help(self, args: List[str]):
        """Display help for all commands or a specific command."""
        try:
            if args:
                cmd = args[0]
                if cmd in self.COMMANDS:
                    print_formatted_text(HTML(f"<ansigreen>{html.escape(cmd)}</ansigreen>: <ansiblue>{html.escape(self.COMMANDS[cmd])}</ansiblue>\r\n"))
                else:
                    self.crash_handler.raise_crash("Shell", "0xV0E0ERR", f"Unknown command: {cmd}")
            else:
                print_formatted_text(HTML("<b>\r\nAvailable commands:</b>\r\n"))
                max_cmd_length = max(len(cmd) for cmd in self.COMMANDS)
                for cmd, desc in sorted(self.COMMANDS.items()):
                    padded_cmd = html.escape(cmd).ljust(max_cmd_length)
                    print_formatted_text(HTML(f"  <ansigreen>{padded_cmd}</ansigreen>  <ansiblue>{html.escape(desc)}</ansiblue>"))
        except Exception as e:
            self.crash_handler.handle(e, "Help command")

    def run(self):
        self.logger.info("Starting shell loop")
        error_count = 0
        max_errors = 5
        while True:
            try:
                cmd = self.session.prompt()
                parts = cmd.strip().split()
                if not parts:
                    continue
                command = parts[0]
                args = parts[1:]
                self.logger.debug(f"Executing command: {command} with args: {args}")

                if command == "help":
                    self._help(args)
                elif command == "ls":
                    path = args[0] if args else "/"
                    files = self.kernel.list_dir(path)
                    print_formatted_text(HTML("\n".join(f"<ansiyellow>{html.escape(f)}</ansiyellow>" for f in files)))
                elif command == "cat":
                    if not args:
                        print_formatted_text(HTML("<ansired>Usage: cat <path></ansired>"))
                    else:
                        content = self.kernel.read_file(args[0])
                        if content:
                            print_formatted_text(HTML(f"<ansiyellow>{html.escape(content)}</ansiyellow>"))
                elif command == "L.mktxt":
                    if len(args) < 1:
                        print_formatted_text(HTML("<ansired>Usage: L.mktxt <path></ansired>"))
                    else:
                        print_formatted_text(HTML("<b>Content--> </b>"))
                        content = input()
                        self.kernel.create_file(args[0], content)
                        print_formatted_text(HTML(f"<ansigreen>File created: {args[0]}</ansigreen>"))
                elif command == "L.mkdir":
                    if not args:
                        print_formatted_text(HTML("<ansired>Usage: L.mkdir <path></ansired>"))
                    else:
                        self.kernel.create_directory(args[0])
                        print_formatted_text(HTML(f"<ansigreen>Directory created: {args[0]}</ansigreen>"))
                elif command == "L.rm":
                    if not args:
                        print_formatted_text(HTML("<ansired>Usage: L.rm <path></ansired>"))
                    else:
                        self.kernel.remove(args[0])
                        print_formatted_text(HTML(f"<ansigreen>Path removed: {args[0]}</ansigreen>"))
                elif command == "L.chmod":
                    if len(args) < 2:
                        print_formatted_text(HTML(f"<ansired>{html.escape('Usage: L.chmod <path> <perms>')}</ansired>"))
                    else:
                        try:
                            perms = int(args[1], 8)
                            self.kernel.chmod(args[0], perms)
                            print_formatted_text(HTML(f"<ansigreen>Permissions changed: {args[0]} to {oct(perms)}</ansigreen>"))
                        except ValueError:
                            self.crash_handler.raise_crash("Shell", "0xV0E0ERR", f"Invalid permissions: {args[1]}")
                elif command == "adduser":
                    if len(args) < 2:
                        print_formatted_text(HTML("<ansired>Usage: adduser <username> <password> [role]</ansired>"))
                    else:
                        username = args[0]
                        password = args[1]
                        role = args[2] if len(args) > 2 else "user"
                        self.kernel.add_user(username, password, role)
                        print_formatted_text(HTML(f"<ansigreen>User {html.escape(username)} added</ansigreen>"))
                elif command == "deluser":
                    if not args:
                        print_formatted_text(HTML("<ansired>Usage: deluser <username></ansired>"))
                    else:
                        self.kernel.delete_user(args[0])
                        print_formatted_text(HTML(f"<ansigreen>User {html.escape(args[0])} deleted</ansigreen>"))
                elif command == "login":
                    if len(args) < 1:
                        print_formatted_text(HTML(f"<ansired>{html.escape('Usage: login <username> <password>')}</ansired>"))
                    else:
                        username = args[0]
                        password = input(f"Password for {username}: ")
                        if self.kernel.login(username, password):
                            self.tnfs.current_user = username
                            #self.tnfs.current_role = self.kernel.user_manager.get_user_info(username)
                            self.session = PromptSession(f"~{self.tnfs.current_user}--> ", key_bindings=self.bindings)
                            print_formatted_text(HTML(f"<ansigreen>Logged in as {html.escape(username)}</ansigreen>"))
                        else:
                            print_formatted_text(HTML("<ansired>Login failed</ansired>"))
                elif command == "passwd":
                    if len(args) < 1:
                        print_formatted_text(HTML("<ansired>Usage: passwd <username></ansired>"))
                    else:
                        old_password = input("Old password: ")
                        new_password = input("New password: ")
                        if self.kernel.change_password(args[0], old_password, new_password):
                            print_formatted_text(HTML(f"<ansigreen>Password changed</ansigreen>"))
                        else:
                            print_formatted_text(HTML("<ansired>Password change failed</ansired>"))
                elif command == "who":
                    sessions = self.kernel.get_active_sessions()
                    for s in sessions:
                        print_formatted_text(HTML(f"<ansigreen>Session {s['session_id']}: {html.escape(s['username'])} (since {html.escape(str(s['login_time']))})</ansigreen>"))
                elif command == "whoami":
                    session_id = self.kernel.user_manager.current_session_id
                    if session_id:
                        info = self.kernel.get_session_info(session_id)
                        print_formatted_text(HTML(f"<ansigreen>Current user: {html.escape(info['username'])}, Session ID: {info['session_id']}, Login time: {html.escape(str(info['login_time']))}</ansigreen>"))
                    else:
                        print_formatted_text(HTML("<ansired>No active session</ansired>"))
                elif command == "logout":
                    if not self.kernel.user_manager.current_session_id:
                        print_formatted_text(HTML("<ansired>No active session</ansired>"))
                    else:
                        self.kernel.logout(self.kernel.user_manager.current_session_id)
                        self.tnfs.current_user = "root"
                        self.tnfs.current_role = "root"
                        self.session = PromptSession(f"~{self.tnfs.current_user}--> ", key_bindings=self.bindings)
                        print_formatted_text(HTML(f"<ansigreen>Logged out</ansigreen>"))
                elif command == "SEL":
                    if len(args) != 1:
                        print_formatted_text(HTML("<ansired>Usage: SEL <enforcing/permissive></ansired>"))
                    else:
                        mode = args[0].lower()
                        if mode not in ["enforcing", "permissive"]:
                            self.crash_handler.raise_crash("Shell", "0xV0E0ERR", "Invalid SELinux mode")
                        self.kernel.selinux.set_mode(mode)
                        print_formatted_text(HTML(f"<ansigreen>SELinux mode set to {html.escape(mode)}</ansigreen>"))
                elif command == "addrule":
                    if len(args) < 4:
                        print_formatted_text(HTML("<ansired>Usage: addrule <path> <operation> <type> <subjects...></ansired>"))
                    else:
                        path, operation, obj_type, *subjects = args
                        self.kernel.selinux.add_rule(path, operation, subjects, obj_type)
                        print_formatted_text(HTML(f"<ansigreen>Rule added: {html.escape(operation)} on {html.escape(path)} for {html.escape(str(subjects))} (type: {html.escape(obj_type)})</ansigreen>"))
                elif command == "rmrule":
                    if len(args) < 3:
                        print_formatted_text(HTML("<ansired>Usage: rmrule <path> <operation> <subjects...></ansired>"))
                    else:
                        path, operation, *subjects = args
                        self.kernel.selinux.remove_rule(path, operation, subjects)
                        print_formatted_text(HTML(f"<ansigreen>Rule removed: {html.escape(operation)} on {html.escape(path)} for {html.escape(str(subjects))}</ansigreen>"))
                elif command == "listrules":
                    rules = self.kernel.selinux.list_rules()
                    for path, rule in rules.items():
                        print_formatted_text(HTML(f"<ansigreen>{html.escape(path)} (type: {html.escape(rule.get('type', 'any'))}):</ansigreen>"))
                        for op, subjects in rule.items():
                            if op != "type":
                                print_formatted_text(HTML(f"  <ansiblue>{html.escape(op)}: {html.escape(str(subjects))}</ansiblue>"))
                elif command == "resetSEL":
                    self.kernel.selinux.reset_policies()
                    print_formatted_text(HTML(f"<ansigreen>SELinux policies reset to default</ansigreen>"))
                elif command == "L.warn":
                    self.kernel.crash_handler.warn("WARNING", "0xU0W0WRN", "Test user warning")
                    print_formatted_text(HTML(f"<ansigreen>Test warning triggered</ansigreen>"))
                elif command == "auditlogs":
                    logs = self.kernel.selinux.get_audit_logs()
                    for log in logs:
                        print_formatted_text(HTML(
                            f"<ansigreen>[{html.escape(str(log['timestamp']))}] Session {log['session_id']}: {html.escape(log['username'])} ({html.escape(log['role'])}) "
                            f"{html.escape(log['result'])} {html.escape(log['operation'])} on {html.escape(log['path'])} ({html.escape(log['mode'])})</ansigreen>"
                        ))
                elif command == "exit":
                    print_formatted_text(HTML("<ansigreen>Exiting shell</ansigreen>"))
                    break
                else:
                    self.crash_handler.raise_crash("Shell", "0xV0E0ERR", f"Unknown command: {command}")
                error_count = 0  # Сброс счетчика ошибок при успешном выполнении
            except TunderCrash as e:
                print_formatted_text(HTML(f"<ansired>Error: {html.escape(str(e))}</ansired>"))
            except Exception as e:
                self.crash_handler.handle(e, "Shell command")
                error_count += 1
                if error_count >= max_errors:
                    print_formatted_text(HTML("<ansired>\r\nToo many errors in shell loop, exiting...</ansired>\r\n"))
                    self.logger.error("Exiting shell due to repeated errors")
                    break
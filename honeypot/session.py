from __future__ import annotations

import posixpath
from dataclasses import dataclass, field

from .filesystem import (
    DIRS, FILES, FAKE_AUTHORIZED_KEYS, FAKE_SECRETS, FAKE_BASHRC,
    FAKE_PROFILE, FAKE_BASH_HISTORY, ROOT_BASH_HISTORY, FAKE_ROTATE_KEYS_SCRIPT,
    FAKE_MYSQL_HISTORY, FAKE_KNOWN_HOSTS, FAKE_ID_RSA, FAKE_ID_RSA_PUB,
    STANDARD_PASSWD_USERNAMES,
)


@dataclass
class Session:
    session_id: str
    client_ip: str
    username: str
    hostname: str
    cwd: str = field(init=False)
    paths: dict[str, str] = field(default_factory=dict)
    dir_cache: dict[str, list[str]] = field(default_factory=dict)
    files: dict[str, str] = field(default_factory=dict)
    # Commands submitted this session, in order -- shared by up/down arrow
    # recall (shell.py) and the 'history' command (local_command.py).
    history: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.cwd = self.home_dir()
        self._load_filesystem()

    def _seed_home(self, home: str, is_root: bool) -> None:
        home_names = [".bashrc", ".profile", ".bash_history", ".ssh", "secrets.txt"]
        home_names.append("rotate_keys.sh" if is_root else ".mysql_history")
        self.paths[home] = "dir"
        self.dir_cache[home] = home_names

        home_files = [
            (".bashrc", FAKE_BASHRC),
            (".profile", FAKE_PROFILE),
            (".bash_history", ROOT_BASH_HISTORY if is_root else FAKE_BASH_HISTORY),
        ]
        if is_root:
            home_files.append(("rotate_keys.sh", FAKE_ROTATE_KEYS_SCRIPT))
        else:
            home_files.append((".mysql_history", FAKE_MYSQL_HISTORY))

        for name, content in home_files:
            path = f"{home}/{name}"
            self.paths[path] = "file"
            self.files[path] = content

        ssh_dir = f"{home}/.ssh"
        self.paths[ssh_dir] = "dir"
        self.dir_cache[ssh_dir] = ["authorized_keys", "known_hosts", "id_rsa", "id_rsa.pub"]

        ssh_files = [
            ("authorized_keys", FAKE_AUTHORIZED_KEYS),
            ("known_hosts", FAKE_KNOWN_HOSTS),
            ("id_rsa", FAKE_ID_RSA),
            ("id_rsa.pub", FAKE_ID_RSA_PUB),
        ]
        for name, content in ssh_files:
            path = f"{ssh_dir}/{name}"
            self.paths[path] = "file"
            self.files[path] = content

        secrets = f"{home}/secrets.txt"
        self.paths[secrets] = "file"
        self.files[secrets] = FAKE_SECRETS

    def _load_filesystem(self) -> None:
        for path, names in DIRS.items():
            self.paths[path] = "dir"
            self.dir_cache[path] = list(names)
        for path, content in FILES.items():
            self.paths[path] = "file"
            self.files[path] = content

        if self.username not in STANDARD_PASSWD_USERNAMES:
            self.files["/etc/passwd"] += f"\n{self.username}:x:1000:1000::{self.home_dir()}:/bin/bash"
            self.files["/etc/shadow"] += f"\n{self.username}:*:19800:0:99999:7:::"

        is_root = self.username == "root"
        self._seed_home(self.home_dir(), is_root)
        # /root always exists on a real box (just permission-gated) -- seed it
        # for every session so 'sudo'/'su' have real content to unlock, not
        # just an empty "No such file or directory" once elevated.
        if not is_root:
            self._seed_home("/root", True)
            self.dir_cache.setdefault("/home", []).append(self.username)

    def home_dir(self) -> str:
        return "/root" if self.username == "root" else f"/home/{self.username}"

    def resolve_path(self, arg: str) -> str:
        if not arg or arg == "~":
            return self.home_dir()
        if arg.startswith("~/"):
            arg = posixpath.join(self.home_dir(), arg[2:])
        if not arg.startswith("/"):
            arg = posixpath.join(self.cwd, arg)
        return posixpath.normpath(arg)

    def prompt_cwd(self) -> str:
        home = self.home_dir()
        if self.cwd == home:
            return "~"
        if self.cwd.startswith(home + "/"):
            return "~" + self.cwd[len(home):]
        return self.cwd

    def is_root_locked(self, path: str) -> bool:
        return self.username != "root" and (path == "/root" or path.startswith("/root/"))

    def mark(self, path: str, status: str) -> None:
        self.paths[path] = status
        parent, base = posixpath.split(path)
        names = self.dir_cache.get(parent)
        if names is None:
            return
        if status == "deleted":
            if base in names:
                names.remove(base)
        elif base not in names:
            names.append(base)

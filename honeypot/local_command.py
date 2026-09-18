from __future__ import annotations

import fnmatch
import posixpath
import shlex
import time

from .logger import log_event
from .session import Session

# Paths that are always flagged if read, regardless of command -- SSH private
# Keys and shadow file are the classic things an attacker goes looking for.
_SENSITIVE_SUFFIXES = ("/id_rsa",)
_SENSITIVE_PATHS = {"/etc/shadow"}

# Logs a 'suspicous.activity' event if the given path is one of the sensitive ones above.
def _flag_sensitive_read(session: Session, path: str) -> None:
    if path in _SENSITIVE_PATHS or path.endswith(_SENSITIVE_SUFFIXES):
        log_event(
            session.client_ip, "ssh", "suspicious.activity",
            {"session": session.session_id, "detail": f"read attempt: {path}"},
        )

# Returns the current working directory
def _pwd(session: Session, arg: list[str]):
    if arg:
        return None
    return session.cwd

# Returns the current username
def _whoami(session: Session, arg: list[str]):
    if arg:
        return None
    return session.username

# Returns the session's hostname
def _hostname(session: Session, arg: list[str]):
    if arg:
        return None
    return session.hostname

# Returns a fake uid/gid line, root or a regular user depending
# on who's logged in.
def _id(session: Session, arg: list[str]):
    if arg:
        return None
    uid = 0 if session.username == "root" else 1000
    return f"uid={uid}({session.username}) gid={uid}({session.username}) groups={uid}({session.username})"

# Parses uname's flags (-a, -s, -n, -r, -v, -m, -o) and returns the matching fields.
def _uname(session: Session, arg: list[str]):
    valid = set("asnrvmo")
    flags = set()
    for a in arg:
        if not a.startswith("-"):
            return None
        flags.update(a[1:])
    if flags - valid:
        return None
    if not flags or "a" in flags:
        return f"Linux {session.hostname} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux"
    parts = []
    if "s" in flags:
        parts.append("Linux")
    if "n" in flags:
        parts.append(session.hostname)
    if "r" in flags:
        parts.append("5.15.0-91-generic")
    if "v" in flags:
        parts.append("#101-Ubuntu SMP")
    if "m" in flags:
        parts.append("x86_64")
    if "o" in flags:
        parts.append("GNU/Linux")
    return " ".join(parts)

# Returns the current date/time, formatted like the real 'date' command.
def _date(session: Session, arg: list[str]):
    if arg:
        return None
    return time.strftime("%a %b %d %H:%M:%S UTC %Y", time.gmtime())

# Returns a fake network interface listing.
def _ifconfig(session: Session, arg: list[str]):
    if arg:
        return None
    return (
        "eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500\n"
        "        inet 10.0.2.15  netmask 255.255.255.0  broadcast 10.0.2.255\n"
        "        ether 08:00:27:4e:66:a1  txqueuelen 1000  (Ethernet)\n"
        "lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536\n"
        "        inet 127.0.0.1  netmask 255.0.0.0"
    )

# Returns a fake 'ip' command listing, same info as ifconfig in a different format.
def _ip(session: Session, arg: list[str]):
    if arg:
        return None
    return (
        "1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"
        "    inet 127.0.0.1/8 scope host lo\n"
        "2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500\n"
        "    inet 10.0.2.15/24 brd 10.0.2.255 scope global eth0"
    )

# Changes the session's current directory, checking 
# if the target exists and isn't root-locked
def _cd(session: Session, arg: list[str]):
    a = arg[0] if arg else ""
    target = session.resolve_path(a)
    if session.is_root_locked(target):
        return f"-bash: cd: {a or target}: Permission denied"
    status = session.paths.get(target)
    if status == "dir":
        session.cwd = target
        return ""
    if status == "file":
        return f"-bash: cd: {a or target}: Not a directory"
    return f"-bash: cd: {a or target}: No such file or directory"

# Creates each target as an empty file
# or does nothing if it already exist
def _touch(session: Session, arg: list[str]):
    targets = [a for a in arg if not a.startswith("-")]
    if not targets:
        return "touch: missing file operand"
    for a in targets:
        path = session.resolve_path(a)
        session.mark(path, "file")
        session.files.setdefault(path, "")
    return ""

# Creates each target as a directory
def _mkdir(session: Session, arg: list[str]):
    targets = [a for a in arg if not a.startswith("-")]
    if not targets:
        return "mkdir: missing operand"
    for a in targets:
        path = session.resolve_path(a)
        session.mark(path, "dir")
        session.dir_cache.setdefault(path, [])
    return ""

# Removes each target directory only if it's empty
def _rmdir(session: Session, arg: list[str]):
    targets = [a for a in arg if not a.startswith("-")]
    if not targets:
        return "rmdir: missing operand"
    for a in targets:
        path = session.resolve_path(a)
        status = session.paths.get(path)
        if status is None or status == "deleted":
            return f"rmdir: failed to remove '{a}': No such file or directory"
        if status != "dir":
            return f"rmdir: failed to remove '{a}': Not a directory"
        if session.dir_cache.get(path):
            return f"rmdir: failed to remove '{a}': Directory not empty"
        session.mark(path, "deleted")
        session.dir_cache.pop(path, None)
    return ""

# Removes each target file, or a directory too if -r/-R was given
def _rm(session: Session, arg: list[str]):
    flags = [a for a in arg if a.startswith("-")]
    targets = [a for a in arg if not a.startswith("-")]
    if not targets:
        return "rm: missing operand"
    recursive = any(c in "rR" for f in flags for c in f[1:])
    for a in targets:
        path = session.resolve_path(a)
        status = session.paths.get(path)
        if status is None or status == "deleted":
            return f"rm: cannot remove '{a}': No such file or directory"
        if status == "dir" and not recursive:
            return f"rm: cannot remove '{a}': Is a directory"
        session.mark(path, "deleted")
        session.dir_cache.pop(path, None)
        session.files.pop(path, None)
    return ""

# Lists the content of a directoy, honoring -a/-A for hidden entries
def _ls(session: Session, arg: list[str]):
    flags = [a for a in arg if a.startswith("-")]
    targets = [a for a in arg if not a.startswith("-")]
    show_all = any(c in "aA" for f in flags for c in f[1:])
    target = session.resolve_path(targets[0]) if targets else session.cwd
    label = targets[0] if targets else target
    if session.is_root_locked(target):
        return f"ls: cannot open directory '{label}': Permission denied"
    status = session.paths.get(target)
    if status == "file":
        return label
    if status != "dir":
        return f"ls: cannot access '{label}': No such file or directory"
    names = session.dir_cache.get(target, [])
    if show_all:
        names = list(names) + [".", ".."]
    else:
        names = [n for n in names if not n.startswith(".")]
    if not names:
        return ""
    return "  ".join(sorted(names))

# Prints the content of each target file, checking permissions along the way.
def _cat(session: Session, arg: list[str]):
    targets = [a for a in arg if not a.startswith("-")]
    if not targets:
        return "cat: missing operand"
    outputs = []
    for a in targets:
        path = session.resolve_path(a)
        if session.is_root_locked(path):
            return f"cat: {a}: Permission denied"
        status = session.paths.get(path)
        if status == "dir":
            return f"cat: {a}: Is a directory"
        if status != "file":
            return f"cat: {a}: No such file or directory"
        _flag_sensitive_read(session, path)
        if path == "/etc/shadow" and session.username != "root":
            return f"cat: {a}: Permission denied"
        outputs.append(session.files.get(path, ""))
    return "\n".join(outputs)

# Prints its argument back, space-seperated.
def _echo(session: Session, arg: list[str]):
    return " ".join(arg)

# Fakes a failed wget download and logs the attempted URL.
def _wget(session: Session, arg: list[str]):
    urls = [a for a in arg if not a.startswith("-")]
    if not urls:
        return "wget: missing URL"
    url = urls[0]
    host = url.split("//")[-1].split("/")[0]
    log_event(
        session.client_ip, "ssh", "fetch.attempt",
        {"session": session.session_id, "command": "wget", "url": url},
    )
    return (
        f"--{time.strftime('%Y-%m-%d %H:%M:%S')}--  {url}\n"
        f"Resolving {host}... failed: Name or service not known.\n"
        f"wget: unable to resolve host address '{host}'"
    )

# Fakes a failed curl download and logs the attempted URL.
def _curl(session: Session, arg: list[str]):
    urls = [a for a in arg if not a.startswith("-")]
    if not urls:
        return "curl: try 'curl --help' for more information"
    url = urls[0]
    host = url.split("//")[-1].split("/")[0]
    log_event(
        session.client_ip, "ssh", "fetch.attempt",
        {"session": session.session_id, "command": "curl", "url": url},
    )
    return f"curl: (6) Could not resolve host: {host}"

# Returns a fake process listing.
def _ps(session: Session, arg: list[str]):
    return (
        "  PID TTY          TIME CMD\n"
        "    1 ?        00:00:01 systemd\n"
        "  412 ?        00:00:00 sshd\n"
        " 1337 pts/0    00:00:00 bash\n"
        " 1402 pts/0    00:00:00 ps"
    )

# Returns a fake active-connection listing, showing the attackers
# own IP as the peer.
def _netstat(session: Session, arg: list[str]):
    return (
        "Active Internet connections (w/o servers)\n"
        "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
        f"tcp        0      0 {session.hostname}:ssh        {session.client_ip}:51422        ESTABLISHED"
    )

# Returns the session command histort
def _history(session: Session, arg: list[str]):
    if not session.history:
        return ""
    return "\n".join(f"{i:>5}  {cmd}" for i, cmd in enumerate(session.history, start=1))

# Handles 'sudo' with no command or with '-l' -- 'sudo <command>' itself is
# intercepted earlier in shell.py so it can prompt for a password.
def _sudo(session: Session, arg: list[str]):
    if not arg:
        return "usage: sudo [-h] [-l] command"
    if arg == ["-l"]:
        return (
            f"Matching Defaults entries for {session.username} on {session.hostname}:\n"
            "    env_reset, mail_badpass\n\n"
            f"User {session.username} may run the following commands on {session.hostname}:\n"
            "    (ALL : ALL) ALL"
        )
    return None


_WHICH_PATHS = {
    "bash": "/bin/bash", "sh": "/bin/sh", "ls": "/bin/ls", "cat": "/bin/cat",
    "pwd": "/bin/pwd", "echo": "/bin/echo", "grep": "/bin/grep", "find": "/usr/bin/find",
    "wget": "/usr/bin/wget", "curl": "/usr/bin/curl", "python3": "/usr/bin/python3",
    "perl": "/usr/bin/perl", "nc": "/bin/nc", "ssh": "/usr/bin/ssh", "sudo": "/usr/bin/sudo",
    "su": "/bin/su", "nano": "/bin/nano", "vi": "/usr/bin/vi", "top": "/usr/bin/top",
    "ps": "/bin/ps", "netstat": "/bin/netstat", "head": "/usr/bin/head", "tail": "/usr/bin/tail",
}

# Looks up each name in _WHICH_PATHS and returns the
# ones found, like the real 'which'
def _which(session: Session, arg: list[str]):
    names = [a for a in arg if not a.startswith("-")]
    if not names:
        return ""
    found = [_WHICH_PATHS[n] for n in names if n in _WHICH_PATHS]
    return "\n".join(found)

# Returns a fake set of enviroment vairables
def _env(session: Session, arg: list[str]):
    return (
        "SHELL=/bin/bash\n"
        f"PWD={session.cwd}\n"
        f"LOGNAME={session.username}\n"
        f"HOME={session.home_dir()}\n"
        "LANG=en_US.UTF-8\n"
        f"USER={session.username}\n"
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    )

# Returns a fake 'top' snapshot.
def _top(session: Session, arg: list[str]):
    return (
        "top - 12:00:00 up 3 days,  2:14,  1 user,  load average: 0.08, 0.05, 0.01\n"
        "Tasks:  92 total,   1 running,  91 sleeping,   0 stopped,   0 zombie\n"
        "%Cpu(s):  0.3 us,  0.2 sy,  0.0 ni, 99.4 id,  0.1 wa\n"
        "MiB Mem :   1998.0 total,   1220.4 free,    210.3 used,    567.3 buff/cache\n"
        "MiB Swap:      0.0 total,      0.0 free,      0.0 used.   1612.1 avail Mem\n"
        "\n"
        "  PID USER      PR  NI    VIRT    RES    SHR S  %CPU  %MEM     TIME+ COMMAND\n"
        "    1 root      20   0   22200   4100   3200 S   0.0   0.2   0:01.23 systemd\n"
        "  412 root      20   0   14200   3200   2600 S   0.0   0.2   0:00.05 sshd\n"
        f" 1337 {session.username:<9} 20   0    9200   3800   3100 S   0.0   0.2   0:00.02 bash\n"
        f" 1500 {session.username:<9} 20   0    8300   3400   2900 R   0.0   0.2   0:00.00 top"
    )

# Returns 'no crontab' for '-l', or nothing otherwise
def _crontab(session: Session, arg: list[str]):
    if arg != ["-l"]:
        return None
    return f"no crontab for {session.username}"

# Shared implementation behind both head and tail: parses '-n'/'-<N>',
# then returns the first and last N lines of the target file.
def _read_n_lines(session: Session, arg: list[str], from_end: bool):
    cmd = "tail" if from_end else "head"
    n = 10
    targets = []
    i = 0
    while i < len(arg):
        a = arg[i]
        if a == "-n" and i + 1 < len(arg):
            try:
                n = int(arg[i + 1])
            except ValueError:
                pass
            i += 2
            continue
        if a.startswith("-") and a[1:].isdigit():
            n = int(a[1:])
            i += 1
            continue
        if not a.startswith("-"):
            targets.append(a)
        i += 1
    if not targets:
        return f"{cmd}: missing operand"
    a = targets[0]
    path = session.resolve_path(a)
    if session.is_root_locked(path):
        return f"{cmd}: cannot open '{a}' for reading: Permission denied"
    status = session.paths.get(path)
    if status == "dir":
        return f"{cmd}: error reading '{a}': Is a directory"
    if status != "file":
        return f"{cmd}: cannot open '{a}' for reading: No such file or directory"
    _flag_sensitive_read(session, path)
    if path == "/etc/shadow" and session.username != "root":
        return f"{cmd}: cannot open '{a}' for reading: Permission denied"
    lines = session.files.get(path, "").split("\n")
    selected = lines[-n:] if from_end else lines[:n]
    return "\n".join(selected)

# Returns the first N lines of a file, via _read_n_lines.
def _head(session: Session, arg: list[str]):
    return _read_n_lines(session, arg, from_end=False)

# Returns the last N lines of a file, via _read_n_lines.
def _tail(session: Session, arg: list[str]):
    return _read_n_lines(session, arg, from_end=True)

# No pager here, just dumps the file like cat.
def _less(session: Session, arg: list[str]):
    return _cat(session, arg)

# Same as less, no actual paging.
def _more(session: Session, arg: list[str]):
    return _cat(session, arg)

# Walks the fake filesystem under the given root, filtering by -type and -name
def _find(session: Session, arg: list[str]):
    targets = [a for a in arg if not a.startswith("-")]
    root = session.resolve_path(targets[0]) if targets else session.cwd
    label = targets[0] if targets else root
    if session.paths.get(root) not in ("dir", "file"):
        return f"find: '{label}': No such file or directory"

    type_filter = None
    name_filter = None
    i = 0
    while i < len(arg):
        if arg[i] == "-type" and i + 1 < len(arg):
            type_filter = arg[i + 1]
            i += 2
            continue
        if arg[i] == "-name" and i + 1 < len(arg):
            name_filter = arg[i + 1]
            i += 2
            continue
        if arg[i] == "-perm":
            return ""  # nothing in this fake filesystem carries SUID/SGID bits
        i += 1

    prefix = root if root == "/" else root + "/"
    results = []
    for path, status in session.paths.items():
        if status == "deleted":
            continue
        if path != root and not path.startswith(prefix):
            continue
        if session.is_root_locked(path):
            continue
        if type_filter == "f" and status != "file":
            continue
        if type_filter == "d" and status != "dir":
            continue
        if name_filter and not fnmatch.fnmatch(posixpath.basename(path), name_filter):
            continue
        results.append(path)
    return "\n".join(sorted(results))

# Searhes file content for a pattern, either one file at a time
# or recursively under a directory.
def _grep(session: Session, arg: list[str]):
    recursive = False
    pattern = None
    targets = []
    for a in arg:
        if a in ("-r", "-R"):
            recursive = True
        elif a.startswith("-"):
            continue
        elif pattern is None:
            pattern = a
        else:
            targets.append(a)
    if pattern is None:
        return "Usage: grep [OPTION]... PATTERN [FILE]..."
    if not targets:
        return "grep: missing file operand"

    results = []
    if recursive:
        root = session.resolve_path(targets[0])
        prefix = root if root == "/" else root + "/"
        for path, status in sorted(session.paths.items()):
            if status != "file" or session.is_root_locked(path):
                continue
            if path != root and not path.startswith(prefix):
                continue
            if path == "/etc/shadow" and session.username != "root":
                continue
            for line in session.files.get(path, "").split("\n"):
                if pattern in line:
                    results.append(f"{path}:{line}")
    else:
        for a in targets:
            path = session.resolve_path(a)
            if session.is_root_locked(path):
                results.append(f"grep: {a}: Permission denied")
                continue
            status = session.paths.get(path)
            if status != "file":
                results.append(f"grep: {a}: No such file or directory")
                continue
            if path == "/etc/shadow" and session.username != "root":
                results.append(f"grep: {a}: Permission denied")
                continue
            for line in session.files.get(path, "").split("\n"):
                if pattern in line:
                    label = f"{a}:" if len(targets) > 1 else ""
                    results.append(f"{label}{line}")
    return "\n".join(results)

# Maps each command name to the function that implements it.
LOCAL_COMMANDS = {
    "pwd": _pwd,
    "whoami": _whoami,
    "hostname": _hostname,
    "id": _id,
    "uname": _uname,
    "date": _date,
    "ifconfig": _ifconfig,
    "ip": _ip,
    "cd": _cd,
    "touch": _touch,
    "mkdir": _mkdir,
    "rm": _rm,
    "rmdir": _rmdir,
    "ls": _ls,
    "cat": _cat,
    "echo": _echo,
    "wget": _wget,
    "curl": _curl,
    "ps": _ps,
    "netstat": _netstat,
    "history": _history,
    "sudo": _sudo,
    "which": _which,
    "env": _env,
    "printenv": _env,
    "top": _top,
    "crontab": _crontab,
    "head": _head,
    "tail": _tail,
    "less": _less,
    "more": _more,
    "find": _find,
    "grep": _grep,
}

# Filters that can appear after a '|' in a pipeline. Only plain-text
# transforms are supported -- nothing here models real stdin streaming,
# so a piped stage just re-processes the text the previous stage produced.
_PIPE_FILTERS = {"grep", "head", "tail", "wc"}

# Prefixes that mark a handler's return value as an *error* rather than
# real output -- used to decide whether '&&'/'||' should short-circuit.
# Heuristic, not a real exit-status model, but good enough for a decoy shell.
_ERROR_PREFIXES = (
    "-bash:", "cat:", "ls:", "cd:", "rm:", "mkdir:", "touch:", "wget:",
    "curl:", "find:", "grep:", "head:", "tail:", "usage:",
)


def _looks_like_error(text: str) -> bool:
    return any(text.startswith(p) for p in _ERROR_PREFIXES)

# Applies one pipe-filter stage (grep/head/tail/wc) to already-produced text --
# not real piping, just re-processing the prior stage's output.
def _apply_filter(cmd: str, args: list[str], text: str) -> str:
    if cmd == "grep":
        pattern = next((a for a in args if not a.startswith("-")), None)
        if pattern is None:
            return text
        return "\n".join(line for line in text.split("\n") if pattern in line)
    if cmd in ("head", "tail"):
        n = 10
        for i, a in enumerate(args):
            if a == "-n" and i + 1 < len(args):
                try:
                    n = int(args[i + 1])
                except ValueError:
                    pass
        lines = text.split("\n")
        return "\n".join(lines[:n] if cmd == "head" else lines[-n:])
    if cmd == "wc":
        lines = text.split("\n") if text else []
        words = text.split()
        chars = len(text)
        if "-l" in args:
            return str(len(lines))
        if "-w" in args:
            return str(len(words))
        if "-c" in args:
            return str(chars)
        return f"{len(lines)} {len(words)} {chars}"
    return text

# Returns the index of the first occurrence of any string in `targets` that's
# outside quotes, or -1. `targets` are tried longest-first per position so
# '&&'/'||' get recognized before a bare ';' would be.
def _find_unquoted(s: str, targets: tuple[str, ...]) -> int:
    in_single = in_double = False
    i, n = 0, len(s)
    while i < n:
        ch = s[i]
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif not in_single and not in_double:
            for t in targets:
                if s[i : i + len(t)] == t:
                    return i
        i += 1
    return -1

# Splits a command line on top-level ';', '&&', '||'. Returns a list of
# (operator_before, segment) pairs, where operator_before is '' for the first segment.
def _split_chain(line: str) -> list[tuple[str, str]]:
    segments = []
    op_before = ""
    rest = line
    while True:
        idx = _find_unquoted(rest, ("&&", "||", ";"))
        if idx == -1:
            segments.append((op_before, rest))
            return segments
        op = rest[idx : idx + 2] if rest[idx : idx + 2] in ("&&", "||") else ";"
        segments.append((op_before, rest[:idx]))
        op_before = op
        rest = rest[idx + len(op) :]

# Splits a pipeline segement off '|' into its component stages.
def _split_pipeline(segment: str) -> list[str]:
    parts = []
    idx = _find_unquoted(segment, ("|",))
    while idx != -1:
        parts.append(segment[:idx])
        segment = segment[idx + 1 :]
        idx = _find_unquoted(segment, ("|",))
    parts.append(segment)
    return parts

# Splits off a trailing '>' or '>>' redirect, returning the command part,
# the target path (or None), and whether it's append mode.
def _strip_redirect(segment: str) -> tuple[str, str | None, bool]:
    idx = _find_unquoted(segment, (">>", ">"))
    if idx == -1:
        return segment, None, False
    append = segment[idx : idx + 2] == ">>"
    before = segment[:idx]
    after = segment[idx + 2 :] if append else segment[idx + 1 :]
    target = after.strip()
    if not target:
        return segment, None, False
    return before, target, append


def _run_pipeline(segment: str, session: Session):
    stages = _split_pipeline(segment)
    try:
        first_parts = shlex.split(stages[0])
    except ValueError:
        return None
    if not first_parts:
        return None
    cmd, args = first_parts[0], first_parts[1:]
    handler = LOCAL_COMMANDS.get(cmd)
    if handler is None:
        return None
    text = handler(session, args)
    if text is None:
        return None
    for stage in stages[1:]:
        try:
            stage_parts = shlex.split(stage)
        except ValueError:
            break
        if not stage_parts:
            continue
        fcmd, fargs = stage_parts[0], stage_parts[1:]
        if fcmd not in _PIPE_FILTERS:
            break
        text = _apply_filter(fcmd, fargs, text)
    return text

# looks up and runs a single command's handler by name,
# without chaining/pipe/redirects
def try_local_command(command: str, session: Session):
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts:
        return None
    cmd, args = parts[0], parts[1:]
    handler = LOCAL_COMMANDS.get(cmd)
    if handler is None:
        return None
    return handler(session, args)

# Entry point used by shell.py: handles ';'/'&&'/'||' chaining, '|' pipelines
# (grep/head/tail/wc only), and '>'/'>>' redirection, dispatching each
# individual command through try_local_command/LOCAL_COMMANDS.
def run_command_line(line: str, session: Session) -> str:
    outputs = []
    last_failed = False
    for op, raw_segment in _split_chain(line):
        segment = raw_segment.strip()
        if not segment:
            continue
        if op == "&&" and last_failed:
            continue
        if op == "||" and not last_failed:
            continue

        segment, redirect_target, append = _strip_redirect(segment)
        segment = segment.strip()
        if not segment:
            continue

        result = _run_pipeline(segment, session)
        if result is None:
            try:
                first_word = shlex.split(segment)[0]
            except (ValueError, IndexError):
                first_word = segment
            result = f"-bash: {first_word}: command not found"
            last_failed = True
        else:
            last_failed = _looks_like_error(result)

        if redirect_target:
            path = session.resolve_path(redirect_target)
            session.mark(path, "file")
            if append and session.files.get(path):
                session.files[path] += "\n" + result
            else:
                session.files[path] = result
            continue

        if result:
            outputs.append(result)
    return "\n".join(outputs)

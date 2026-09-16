import shlex

from .config import HOSTNAME
from .local_command import run_command_line
from .logger import log_event
from .session import Session


def fake_shell(channel, session_id, client_ip, username):
    session = Session(
        session_id=session_id,
        client_ip=client_ip,
        username=username,
        hostname=HOSTNAME,
    )

    def prompt() -> bytes:
        suffix = "#" if session.username == "root" else "$"
        return f"{session.username}@{session.hostname}:{session.prompt_cwd()}{suffix} ".encode()

    channel.send(f"Welcome to {session.hostname}\r\n".encode())
    channel.send(prompt())

    buffer = b""
    history_index = 0
    pending_line = b""
    awaiting_password = False
    pending_action = None

    while True:
        data = channel.recv(1024)
        if not data:
            break

        should_close = False
        i = 0
        while i < len(data):
            seq = data[i : i + 3]
            if seq in (b"\x1b[A", b"\x1b[B", b"\x1b[C", b"\x1b[D"):
                if not awaiting_password:
                    if seq == b"\x1b[A" and session.history and history_index > 0:
                        if history_index == len(session.history):
                            pending_line = buffer
                        history_index -= 1
                        buffer = session.history[history_index].encode()
                        channel.send(b"\r" + prompt() + buffer + b"\x1b[K")
                    elif seq == b"\x1b[B" and history_index < len(session.history):
                        history_index += 1
                        if history_index == len(session.history):
                            buffer = pending_line
                        else:
                            buffer = session.history[history_index].encode()
                        channel.send(b"\r" + prompt() + buffer + b"\x1b[K")
                i += 3
                continue

            ch = bytes([data[i]])

            if ch == b"\x03":  # Ctrl+C -- abort the current line
                buffer = b""
                history_index = len(session.history)
                pending_line = b""
                awaiting_password = False
                pending_action = None
                channel.send(b"^C\r\n" + prompt())
                i += 1
                continue

            if ch == b"\x04":  # Ctrl+D -- EOF on an empty line closes the session
                if not buffer:
                    channel.send(b"logout\r\n")
                    should_close = True
                    break
                i += 1
                continue

            if ch in (b"\x7f", b"\x08"):
                if buffer:
                    buffer = buffer[:-1]
                    if not awaiting_password:
                        channel.send(b"\b \b")
            else:
                if not awaiting_password:
                    channel.send(ch)
                buffer += ch
            i += 1

        if should_close:
            break

        while b"\r" in buffer or b"\n" in buffer:
            newline_positions = [p for p in (buffer.find(b"\r"), buffer.find(b"\n"))if p != -1]
            idx = min(newline_positions)
            line = buffer[:idx]
            rest = buffer[idx + 1:]
            if buffer[idx:idx + 1] == b"\r" and rest[:1] == b"\n":
                rest = rest[1:]
            buffer = rest

            if awaiting_password:
                typed_password = line.strip().decode(errors="ignore")
                awaiting_password = False
                action = pending_action
                pending_action = None
                channel.send(b"\r\n")
                log_event(
                    client_ip, "ssh", "privilege.escalation",
                    {"session": session_id, "method": action[0], "password": typed_password},
                )
                if action[0] == "sudo":
                    original_username = session.username
                    session.username = "root"
                    try:
                        response = run_command_line(action[1], session)
                    finally:
                        session.username = original_username
                    response = response.replace("\n", "\r\n")
                    channel.send(f"{response}\r\n".encode() + prompt())
                else:  # su
                    target, login_shell = action[1], action[2]
                    if target == "root":
                        session.username = "root"
                        if login_shell:
                            session.cwd = session.home_dir()
                        channel.send(prompt())
                    else:
                        channel.send(b"su: Authentication failure\r\n" + prompt())
                continue

            command = line.strip().decode(errors="ignore")

            if not command:
                channel.send(prompt())
                continue

            try:
                parts = shlex.split(command)
            except ValueError:
                parts = []

            if parts and parts[0] == "sudo" and len(parts) > 1 and parts[1:] != ["-l"]:
                session.history.append(command)
                history_index = len(session.history)
                pending_line = b""
                log_event(client_ip, "ssh", "command.input", {"session": session_id, "input": command})
                channel.send(("[sudo] password for " + session.username + ": ").encode())
                awaiting_password = True
                pending_action = ("sudo", " ".join(parts[1:]))
                continue

            if parts and parts[0] == "su":
                rest_parts = [p for p in parts[1:] if p not in ("-", "-l", "--login")]
                login_shell = len(rest_parts) != len(parts) - 1
                target = rest_parts[0] if rest_parts else "root"
                session.history.append(command)
                history_index = len(session.history)
                pending_line = b""
                log_event(client_ip, "ssh", "command.input", {"session": session_id, "input": command})
                channel.send(b"Password: ")
                awaiting_password = True
                pending_action = ("su", target, login_shell)
                continue

            session.history.append(command)
            history_index = len(session.history)
            pending_line = b""

            log_event(client_ip, "ssh", "command.input", {"session": session_id, "input": command})

            if command in ("exit", "logout"):
                should_close = True
                break

            channel.send(b"\n")
            response = run_command_line(command, session)
            response = response.replace("\n", "\r\n")
            channel.send(f"{response}\r\n".encode() + prompt())
        if should_close:
            break
    log_event(client_ip, "ssh", "session.closed", {"session": session_id})
    channel.close()

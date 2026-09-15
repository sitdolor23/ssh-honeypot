import os
import socket
import threading
import uuid

import paramiko

from .config import LISTEN_PORT, HOST_KEY_PATH
from .logger import log_event
from .ssh_interface import HoneypotServer
from .shell import fake_shell


def _load_or_create_host_key() -> paramiko.RSAKey:
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key


HOST_KEY = _load_or_create_host_key()


def handle_connection(client_socket, client_addr):
    client_ip = client_addr[0]
    session_id = uuid.uuid4().hex[:12]

    log_event(client_ip, "ssh", "session.connect", {"session": session_id})

    transport = paramiko.Transport(client_socket)
    transport.add_server_key(HOST_KEY)

    server = HoneypotServer(session_id, client_ip)

    try:
        transport.start_server(server=server)
    except paramiko.SSHException:
        return

    channel = transport.accept(20)
    if channel is None:
        return

    server.event.wait(10)

    try:
        fake_shell(channel, session_id, client_ip, server.username)
    finally:
        transport.close()


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", LISTEN_PORT))
    sock.listen(100)
    print(f"honeypot listening on port {LISTEN_PORT}...")

    while True:
        client_socket, client_addr = sock.accept()
        thread = threading.Thread(target=handle_connection, args=(client_socket, client_addr), daemon=True)
        thread.start()
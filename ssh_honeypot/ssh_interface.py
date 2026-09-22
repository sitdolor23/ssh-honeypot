import threading

import paramiko

from .logger import log_event

# Paramiko calls these methods during the SSH handshake to decide what to
# allow. Every check here says "yes" -- the honeypot accepts any login and
# any request, it just logs what happened along the way.
class HoneypotServer(paramiko.ServerInterface):

    def __init__(self, session_id, client_ip):
        self.session_id = session_id
        self.client_ip = client_ip
        self.event = threading.Event()

    # Called by paramiko when the client tries a password login --
    # logs the attempted username/password, then always accepted it.
    def check_auth_password(self, username, password):
        self.username = username
        log_event(
            self.client_ip, "ssh", "login.attempt",
            {"session": self.session_id, "username": username, "password": password},
        )
        return paramiko.AUTH_SUCCESSFUL

    # Called by Paramiko to check whether a requested channel type is allowed.
    # Only "session" channels (a normal shell session) are approved.
    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED

    # Called by Paramiko when the client asks for an interactive shell.
    # Sets self.event so server.py's handle_connection knows it's safe to start the fake shell.
    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    # Called by Paramiko when the client asks for a pseudo-terminal (needed
    # for a proper interactive session) -- always approved.
    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    # Called by Paramiko to advertise which login methods are available -- password only.
    def get_allowed_auths(self, username):
        return "password"
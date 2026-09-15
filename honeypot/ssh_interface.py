import threading

import paramiko

from .logger import log_event


class HoneypotServer(paramiko.ServerInterface):

    def __init__(self, session_id, client_ip):
        self.session_id = session_id
        self.client_ip = client_ip
        self.event = threading.Event()

    def check_auth_password(self, username, password):
        self.username = username
        log_event(
            self.client_ip, "ssh", "login.attempt",
            {"session": self.session_id, "username": username, "password": password},
        )
        return paramiko.AUTH_SUCCESSFUL

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def get_allowed_auths(self, username):
        return "password"
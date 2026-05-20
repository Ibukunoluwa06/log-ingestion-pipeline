# parsers/auth_log.py
# Parses Linux auth.log format lines into structured dictionaries
# Also classifies the event type for SOC analysis

import re
from dateutil import parser as dateparser

# Same timestamp/host/process pattern as syslog
AUTH_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>\w[\w\-]*)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)$'
)

# These patterns detect what kind of security event the message is
EVENT_PATTERNS = [
    ("failed_login",   re.compile(r'Failed password for', re.IGNORECASE)),
    ("accepted_login", re.compile(r'Accepted password for|Accepted publickey for', re.IGNORECASE)),
    ("invalid_user",   re.compile(r'invalid user', re.IGNORECASE)),
    ("new_user",       re.compile(r'new user:', re.IGNORECASE)),
    ("password_change",re.compile(r'password changed for', re.IGNORECASE)),
    ("sudo_command",   re.compile(r'sudo:', re.IGNORECASE)),
    ("failed_su",      re.compile(r'FAILED su', re.IGNORECASE)),
]


def classify_event(message):
    """
    Looks at the message text and returns an event type label.
    Returns 'generic' if no known pattern matches.
    """
    for event_type, pattern in EVENT_PATTERNS:
        if pattern.search(message):
            return event_type
    return "generic"


def extract_ip(message):
    """
    Pulls an IP address out of the message if one exists.
    Returns None if no IP found.
    """
    ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    match = ip_pattern.search(message)
    return match.group(0) if match else None


def parse(raw_line):
    """
    Takes a raw auth.log string and returns a structured dict.
    Returns None if the line does not match auth.log format.
    """
    raw_line = raw_line.strip()

    match = AUTH_PATTERN.match(raw_line)

    if not match:
        return None

    timestamp_str = match.group('timestamp')
    host          = match.group('host')
    process       = match.group('process')
    pid           = match.group('pid')
    message       = match.group('message')

    # Convert timestamp to ISO format
    try:
        timestamp = dateparser.parse(timestamp_str).isoformat()
    except Exception:
        timestamp = timestamp_str

    # Extra intelligence — classify the event and extract IP
    event_type = classify_event(message)
    source_ip  = extract_ip(message)

    return {
        "timestamp":   timestamp,
        "host":        host,
        "process":     process,
        "pid":         pid,
        "message":     message,
        "event_type":  event_type,
        "source_ip":   source_ip,
        "source_type": "auth_log",
        "raw":         raw_line
    }


def can_parse(raw_line):
    """
    Returns True if this line looks like an auth.log line.
    Auth logs use the same format as syslog so we check the
    process name to differentiate — auth logs come from
    sshd, sudo, useradd, passwd, or su.
    """
    auth_processes = ['sshd', 'sudo', 'useradd', 'passwd', 'su']
    match = AUTH_PATTERN.match(raw_line.strip())
    if not match:
        return False
    process = match.group('process')
    return process in auth_processes

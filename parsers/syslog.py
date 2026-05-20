# parsers/syslog.py
# Parses RFC 3164 syslog format lines into structured dictionaries

import re
from dateutil import parser as dateparser

# This is the pattern we expect a syslog line to follow
# Example: Nov 15 10:01:23 kali-linux sshd[1234]: some message here
SYSLOG_PATTERN = re.compile(
    r'^(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+'
    r'(?P<process>\w[\w\-]*)(?:\[(?P<pid>\d+)\])?:\s+'
    r'(?P<message>.+)$'
)


def parse(raw_line):
    """
    Takes a raw syslog string and returns a structured dict.
    Returns None if the line does not match syslog format.
    """
    raw_line = raw_line.strip()

    # Try to match the line against our syslog pattern
    match = SYSLOG_PATTERN.match(raw_line)

    if not match:
        # Line does not look like syslog — return None
        return None

    # Pull out each named piece from the match
    timestamp_str = match.group('timestamp')
    host          = match.group('host')
    process       = match.group('process')
    pid           = match.group('pid')    # might be None if no PID in line
    message       = match.group('message')

    # Convert the timestamp string into a proper ISO format
    # dateutil handles "Nov 15 10:01:23" automatically
    try:
        timestamp = dateparser.parse(timestamp_str).isoformat()
    except Exception:
        timestamp = timestamp_str  # keep original if parsing fails

    # Build and return the structured result
    return {
        "timestamp":   timestamp,
        "host":        host,
        "process":     process,
        "pid":         pid,
        "message":     message,
        "source_type": "syslog",
        "raw":         raw_line
    }


def can_parse(raw_line):
    """
    Returns True if this line looks like a syslog line.
    Used by parser.py to decide which parser to use.
    """
    return bool(SYSLOG_PATTERN.match(raw_line.strip()))

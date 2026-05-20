# src/parser.py
# Dispatcher — automatically routes each raw log line to the correct parser

import sys
import os

# This line lets Python find the parsers/ folder
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from parsers import auth_log, syslog

# List of all available parsers in priority order
# auth_log must come BEFORE syslog because auth log lines
# also match the syslog pattern — we want the more specific
# parser to get first pick
PARSERS = [
    auth_log,
    syslog,
]


def parse_line(raw_line):
    """
    Takes a single raw log line and returns a structured dict.

    Returns a dict with parsed=True if a parser handled it.
    Returns a dict with parsed=False if no parser could handle it.
    """
    raw_line = raw_line.strip()

    # Skip completely empty lines
    if not raw_line:
        return None

    # Try each parser in order
    for parser in PARSERS:
        if parser.can_parse(raw_line):
            result = parser.parse(raw_line)
            if result:
                result['parsed'] = True
                return result

    # No parser matched — return a dead-letter record
    return {
        "parsed":      False,
        "raw":         raw_line,
        "source_type": "unknown",
        "reason":      "no parser matched this line"
    }


def parse_file(filepath):
    """
    Reads every line in a log file and parses each one.
    Returns two lists:
      - parsed:   successfully parsed events
      - failed:   lines no parser could handle
    """
    parsed  = []
    failed  = []

    try:
        with open(filepath, 'r', errors='replace') as f:
            for line in f:
                result = parse_line(line)

                if result is None:
                    # Empty line — skip silently
                    continue
                elif result.get('parsed') == False:
                    failed.append(result)
                else:
                    parsed.append(result)

    except FileNotFoundError:
        print(f"[ERROR] File not found: {filepath}")
    except PermissionError:
        print(f"[ERROR] Permission denied reading: {filepath}")

    return parsed, failed


def parse_lines(lines):
    """
    Same as parse_file but works on a list of strings
    instead of a file. Useful for testing.
    """
    parsed = []
    failed = []

    for line in lines:
        result = parse_line(line)
        if result is None:
            continue
        elif result.get('parsed') == False:
            failed.append(result)
        else:
            parsed.append(result)

    return parsed, failed


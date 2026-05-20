# src/collector.py
# Reads log files and yields one raw line at a time
# Supports one-shot mode (read whole file) and
# tail mode (keep watching for new lines like `tail -f`)

import os
import time


def read_file(filepath):
    """
    Reads an entire log file from top to bottom.
    Yields one raw line at a time.
    Use this for processing existing/sample log files.
    """
    print(f"[COLLECTOR] Reading file: {filepath}")

    if not os.path.exists(filepath):
        print(f"[COLLECTOR][ERROR] File not found: {filepath}")
        return

    if not os.access(filepath, os.R_OK):
        print(f"[COLLECTOR][ERROR] No read permission: {filepath}")
        return

    with open(filepath, 'r', errors='replace') as f:
        for line in f:
            line = line.strip()
            if line:              # skip empty lines
                yield line

    print(f"[COLLECTOR] Finished reading: {filepath}")


def tail_file(filepath, poll_interval=1.0):
    """
    Watches a log file for new lines continuously.
    Yields each new line as it appears — like running `tail -f`.
    Use this for live log monitoring.

    poll_interval = how many seconds to wait before checking
    for new lines (default: 1 second)
    """
    print(f"[COLLECTOR] Tailing file: {filepath}")

    if not os.path.exists(filepath):
        print(f"[COLLECTOR][ERROR] File not found: {filepath}")
        return

    with open(filepath, 'r', errors='replace') as f:
        # Jump to the end of the file — we only want NEW lines
        f.seek(0, 2)

        while True:
            line = f.readline()

            if line:
                line = line.strip()
                if line:
                    yield line
            else:
                # No new line yet — wait and try again
                time.sleep(poll_interval)


def collect_all(sources):
    """
    Takes a list of source configs from config.yaml and
    reads all of them in one-shot mode.

    Each source config looks like:
    { "type": "file", "name": "syslog", "path": "./tests/samples/sample_syslog.log" }

    Yields tuples of (source_name, raw_line) so the pipeline
    knows which source each line came from.
    """
    for source in sources:
        source_type = source.get('type')
        source_name = source.get('name', 'unknown')
        filepath    = source.get('path')

        if source_type == 'file':
            for line in read_file(filepath):
                yield source_name, line
        else:
            print(f"[COLLECTOR][WARN] Unknown source type: {source_type}")

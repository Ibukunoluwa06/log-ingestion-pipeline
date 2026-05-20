# src/storage.py
# Saves enriched log events to JSON lines file and SQLite database

import json
import sqlite3
import os
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# JSON Lines writer
# Each line in the file is one complete JSON event.
# This format is simple, human-readable, and grep-friendly.
# ---------------------------------------------------------------------------

def write_jsonl(events, filepath):
    """
    Appends a list of enriched events to a JSON lines file.
    Creates the file if it does not exist.
    """
    # Create output directory if it does not exist
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    written = 0

    with open(filepath, 'a') as f:          # 'a' = append, not overwrite
        for event in events:
            try:
                # Convert tags list to JSON-safe format
                line = json.dumps(event, default=str)
                f.write(line + '\n')
                written += 1
            except Exception as e:
                print(f"[STORAGE][ERROR] Could not write event: {e}")

    print(f"[STORAGE] Wrote {written} events to {filepath}")
    return written


def write_dead_letter(failed_events, filepath):
    """
    Saves unparseable log lines to a separate dead-letter file.
    Same format as the main JSON lines file.
    """
    if not failed_events:
        return 0

    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    written = 0

    with open(filepath, 'a') as f:
        for event in failed_events:
            try:
                line = json.dumps(event, default=str)
                f.write(line + '\n')
                written += 1
            except Exception as e:
                print(f"[STORAGE][ERROR] Could not write dead letter: {e}")

    print(f"[STORAGE] Wrote {written} dead-letter events to {filepath}")
    return written


# ---------------------------------------------------------------------------
# SQLite writer
# Creates a table if it does not exist, then inserts events.
# SQLite is a file-based database — no server needed.
# ---------------------------------------------------------------------------

def init_db(db_path):
    """
    Creates the SQLite database and events table if they
    do not already exist. Safe to call multiple times.
    """
    os.makedirs(os.path.dirname(db_path), exist_ok=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS events (
            id             INTEGER PRIMARY KEY AUTOINCREMENT,
            ingest_time    TEXT,
            timestamp      TEXT,
            host           TEXT,
            process        TEXT,
            pid            TEXT,
            source_type    TEXT,
            event_type     TEXT,
            severity       TEXT,
            severity_score INTEGER,
            source_ip      TEXT,
            ip_type        TEXT,
            tags           TEXT,
            message        TEXT,
            raw            TEXT
        )
    ''')

    conn.commit()
    conn.close()
    print(f"[STORAGE] Database ready: {db_path}")


def write_sqlite(events, db_path):
    """
    Inserts a list of enriched events into the SQLite database.
    Skips events that fail to insert without crashing.
    """
    if not events:
        return 0

    init_db(db_path)

    conn    = sqlite3.connect(db_path)
    cursor  = conn.cursor()
    written = 0

    for event in events:
        try:
            # Tags is a list — convert to a comma-separated string for SQLite
            tags = ', '.join(event.get('tags', []))

            cursor.execute('''
                INSERT INTO events (
                    ingest_time, timestamp, host, process, pid,
                    source_type, event_type, severity, severity_score,
                    source_ip, ip_type, tags, message, raw
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event.get('ingest_time'),
                event.get('timestamp'),
                event.get('host'),
                event.get('process'),
                event.get('pid'),
                event.get('source_type'),
                event.get('event_type'),
                event.get('severity'),
                event.get('severity_score'),
                event.get('source_ip'),
                event.get('ip_type'),
                tags,
                event.get('message'),
                event.get('raw')
            ))
            written += 1

        except Exception as e:
            print(f"[STORAGE][ERROR] Could not insert event: {e}")

    conn.commit()
    conn.close()

    print(f"[STORAGE] Inserted {written} events into {db_path}")
    return written


# ---------------------------------------------------------------------------
# Query helpers — useful for testing and the README demo
# ---------------------------------------------------------------------------

def query_high_severity(db_path):
    """Returns all HIGH severity events from the database."""
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, host, event_type, message FROM events "
        "WHERE severity = 'HIGH' ORDER BY timestamp"
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def query_by_ip(db_path, ip_address):
    """Returns all events from a specific IP address."""
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, event_type, severity, message FROM events "
        "WHERE source_ip = ? ORDER BY timestamp",
        (ip_address,)
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def query_brute_force(db_path):
    """Returns all events tagged as brute_force_candidate."""
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT timestamp, host, source_ip, message FROM events "
        "WHERE tags LIKE '%brute_force_candidate%' ORDER BY timestamp"
    )
    rows = cursor.fetchall()
    conn.close()
    return rows


def get_summary(db_path):
    """Returns a quick summary of what is in the database."""
    conn   = sqlite3.connect(db_path)
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM events")
    total = cursor.fetchone()[0]

    cursor.execute(
        "SELECT severity, COUNT(*) FROM events GROUP BY severity"
    )
    by_severity = cursor.fetchall()

    cursor.execute(
        "SELECT event_type, COUNT(*) FROM events "
        "GROUP BY event_type ORDER BY COUNT(*) DESC"
    )
    by_type = cursor.fetchall()

    conn.close()

    return {
        "total_events": total,
        "by_severity":  dict(by_severity),
        "by_type":      dict(by_type)
    }

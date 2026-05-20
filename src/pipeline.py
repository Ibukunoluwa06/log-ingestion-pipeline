# src/pipeline.py
# Main entry point — wires all pipeline stages together
# Usage: python3 src/pipeline.py --config config.yaml

import sys
import os
import json
import argparse

# Make sure Python can find all our modules
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import yaml

from src.collector import collect_all
from src.parser    import parse_line
from src.enricher  import enrich
from src.storage   import write_jsonl, write_dead_letter, write_sqlite, get_summary


# ---------------------------------------------------------------------------
# Config loader
# ---------------------------------------------------------------------------

def load_config(config_path):
    """
    Reads config.yaml and returns it as a Python dictionary.
    Exits with a clear error if the file is missing or invalid.
    """
    if not os.path.exists(config_path):
        print(f"[PIPELINE][ERROR] Config file not found: {config_path}")
        sys.exit(1)

    with open(config_path, 'r') as f:
        try:
            config = yaml.safe_load(f)
            print(f"[PIPELINE] Loaded config: {config_path}")
            return config
        except yaml.YAMLError as e:
            print(f"[PIPELINE][ERROR] Could not parse config: {e}")
            sys.exit(1)


# ---------------------------------------------------------------------------
# Pipeline runner
# ---------------------------------------------------------------------------

def run(config):
    """
    Runs the full pipeline:
    1. Collect raw lines from all sources
    2. Parse each line
    3. Enrich each parsed event
    4. Save to JSON lines and SQLite
    5. Print a summary
    """

    # Pull settings out of config
    sources          = config.get('sources', [])
    json_file        = config.get('output', {}).get('json_file',      './output/events.jsonl')
    db_path          = config.get('output', {}).get('sqlite_db',      './output/logs.db')
    dead_letter_file = config.get('pipeline', {}).get('dead_letter_file', './output/dead_letter.jsonl')

    print()
    print("=" * 55)
    print("   LOG INGESTION PIPELINE — STARTING")
    print("=" * 55)

    # Counters for the final summary
    total_lines   = 0
    parsed_events = []
    failed_events = []

    # Shared dict for brute force detection across all events
    failed_login_counts = {}

    # ---------------------
    # Stage 1: Collect + Parse + Enrich
    # ---------------------
    print("\n[STAGE 1] Collecting and parsing log lines...")

    for source_name, raw_line in collect_all(sources):
        total_lines += 1

        # Parse the raw line
        result = parse_line(raw_line)

        if result is None:
            # Empty line — skip
            continue

        if not result.get('parsed'):
            # Parser could not handle this line
            result['source_name'] = source_name
            failed_events.append(result)
            continue

        # Enrich the parsed event
        enriched = enrich(result, failed_login_counts)
        enriched['source_name'] = source_name
        parsed_events.append(enriched)

    print(f"\n[STAGE 1] Complete.")
    print(f"          Total lines read : {total_lines}")
    print(f"          Successfully parsed: {len(parsed_events)}")
    print(f"          Failed (dead-letter): {len(failed_events)}")

    # ---------------------
    # Stage 2: Save to disk
    # ---------------------
    print("\n[STAGE 2] Saving events to disk...")

    write_jsonl(parsed_events, json_file)
    write_sqlite(parsed_events, db_path)

    if failed_events:
        write_dead_letter(failed_events, dead_letter_file)

    # ---------------------
    # Stage 3: Print summary
    # ---------------------
    print("\n[STAGE 3] Pipeline summary")
    print("-" * 55)

    summary = get_summary(db_path)

    print(f"  Total events stored : {summary['total_events']}")

    print("\n  By severity:")
    for severity, count in sorted(summary['by_severity'].items()):
        bar = '█' * count
        print(f"    {severity:<10} {bar} {count}")

    print("\n  By event type:")
    for event_type, count in sorted(
        summary['by_type'].items(), key=lambda x: x[1], reverse=True
    ):
        print(f"    {str(event_type or 'unknown'):<25} {count}")

    print("\n  Output files:")
    print(f"    JSON  → {json_file}")
    print(f"    DB    → {db_path}")
    if failed_events:
        print(f"    Dead  → {dead_letter_file}")

    print()
    print("=" * 55)
    print("   PIPELINE COMPLETE")
    print("=" * 55)
    print()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == '__main__':
    # Set up command line arguments
    arg_parser = argparse.ArgumentParser(
        description='Log Ingestion Pipeline — parse and enrich log files'
    )
    arg_parser.add_argument(
        '--config',
        default='config.yaml',
        help='Path to config.yaml (default: config.yaml)'
    )
    args = arg_parser.parse_args()

    # Load config and run
    config = load_config(args.config)
    run(config)

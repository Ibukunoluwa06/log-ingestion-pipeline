# src/enricher.py
# Adds extra context and intelligence to parsed log events
# Enrichments: severity scoring, tagging, ingest timestamp,
# private/public IP classification

import re
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# Severity rules
# Each rule is: (event_type, severity_label, severity_score)
# Score runs 1-10. Higher = more serious.
# ---------------------------------------------------------------------------
SEVERITY_RULES = {
    "failed_login":    ("MEDIUM", 5),
    "invalid_user":    ("MEDIUM", 5),
    "accepted_login":  ("LOW",    2),
    "new_user":        ("HIGH",   7),
    "password_change": ("MEDIUM", 5),
    "sudo_command":    ("MEDIUM", 4),
    "failed_su":       ("HIGH",   7),
    "generic":         ("LOW",    1),
}

# Default when event_type is missing or unrecognised
DEFAULT_SEVERITY = ("LOW", 1)


# ---------------------------------------------------------------------------
# IP classification helpers
# ---------------------------------------------------------------------------
PRIVATE_IP_PATTERNS = re.compile(
    r'^(10\.'                       # 10.x.x.x
    r'|172\.(1[6-9]|2[0-9]|3[01])\.'  # 172.16-31.x.x
    r'|192\.168\.'                  # 192.168.x.x
    r'|127\.'                       # loopback
    r'|::1$)'                       # IPv6 loopback
)


def is_private_ip(ip):
    """Returns True if the IP is a private/internal address."""
    if not ip:
        return False
    return bool(PRIVATE_IP_PATTERNS.match(ip))


# ---------------------------------------------------------------------------
# Tagging logic
# Tags are short labels that make filtering easy later.
# e.g. show me all events tagged "brute_force_candidate"
# ---------------------------------------------------------------------------
def generate_tags(event, failed_login_counts):
    """
    Looks at the event and returns a list of relevant tags.
    failed_login_counts is a dict tracking how many failed
    logins we have seen per IP so far in this pipeline run.
    """
    tags = []
    source_ip  = event.get('source_ip')
    event_type = event.get('event_type', '')

    # Tag based on IP type
    if source_ip:
        if is_private_ip(source_ip):
            tags.append('internal_ip')
        else:
            tags.append('external_ip')

    # Track failed logins per IP and tag brute force candidates
    if event_type in ('failed_login', 'invalid_user') and source_ip:
        failed_login_counts[source_ip] = (
            failed_login_counts.get(source_ip, 0) + 1
        )
        if failed_login_counts[source_ip] >= 3:
            tags.append('brute_force_candidate')

    # Tag privileged activity
    if event_type in ('sudo_command', 'new_user', 'password_change'):
        tags.append('privileged_activity')

    # Tag successful logins from external IPs — worth watching
    if event_type == 'accepted_login' and source_ip and not is_private_ip(source_ip):
        tags.append('external_login_success')

    return tags


# ---------------------------------------------------------------------------
# Main enricher
# ---------------------------------------------------------------------------
def enrich(event, failed_login_counts=None):
    """
    Takes a parsed event dict and returns an enriched copy.
    Does not modify the original dict.
    """
    if failed_login_counts is None:
        failed_login_counts = {}

    # Work on a copy — never mutate the input
    enriched = dict(event)

    # 1. Add ingest timestamp — when WE processed this event
    enriched['ingest_time'] = datetime.now(timezone.utc).isoformat()

    # 2. Add severity based on event_type
    event_type = enriched.get('event_type', 'generic')
    severity_label, severity_score = SEVERITY_RULES.get(
        event_type, DEFAULT_SEVERITY
    )
    enriched['severity']       = severity_label
    enriched['severity_score'] = severity_score

    # 3. Classify IP as internal or external
    source_ip = enriched.get('source_ip')
    if source_ip:
        enriched['ip_type'] = 'private' if is_private_ip(source_ip) else 'public'

    # 4. Generate tags
    enriched['tags'] = generate_tags(enriched, failed_login_counts)

    return enriched


def enrich_all(events):
    """
    Enriches a list of events in order.
    Passes a shared failed_login_counts dict across all events
    so brute force detection works across the whole batch.
    """
    failed_login_counts = {}
    return [enrich(event, failed_login_counts) for event in events]

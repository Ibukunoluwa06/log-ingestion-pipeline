# Log Ingestion Pipeline

A lightweight SOC-ready log ingestion pipeline that collects, parses,
normalises, and enriches security logs into structured JSON for downstream
analysis or SIEM feeding.

Built as a beginner-friendly introduction to Security Operations Center
(SOC) tooling using Python.

---

## What it does

- Reads log files from multiple sources simultaneously
- Auto-detects log format (syslog, Linux auth.log) and routes to the correct parser
- Enriches each event with severity scoring, IP classification, and threat tags
- Detects brute force login attempts automatically across the event stream
- Saves all output to JSON Lines and a queryable SQLite database
- Sends unparseable lines to a dead-letter file — nothing is silently dropped

---

## Architecture

**Modules:**
- `src/collector.py` — reads log files line by line
- `src/parser.py` — auto-detects format and routes to the right parser
- `parsers/syslog.py` — handles RFC 3164/5424 syslog format
- `parsers/auth_log.py` — handles Linux auth.log with event classification
- `src/enricher.py` — adds severity, IP type, ingest time, and threat tags
- `src/storage.py` — writes JSON lines and SQLite output

---

## Quickstart

### 1. Clone the repo
```bash
git clone https://github.com/YOUR_USERNAME/log-ingestion-pipeline.git
cd log-ingestion-pipeline
```

### 2. Create and activate virtual environment
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the pipeline
```bash
python3 src/pipeline.py --config config.yaml
```

Sample log files are included in `tests/samples/` so the pipeline
runs immediately without any setup.

---

## Configuration

Edit `config.yaml` to point at your own log files:

```yaml
sources:
  - type: file
    name: syslog
    path: ./tests/samples/sample_syslog.log

  - type: file
    name: auth_log
    path: ./tests/samples/sample_auth.log

output:
  json_file: ./output/events.jsonl
  sqlite_db: ./output/logs.db

pipeline:
  dead_letter_file: ./output/dead_letter.jsonl
  log_level: INFO
```

---

## Output schema

Every parsed and enriched event contains these fields:

| Field           | Type    | Example                          |
|-----------------|---------|----------------------------------|
| timestamp       | string  | 2024-11-15T10:01:23              |
| host            | string  | kali-linux                       |
| process         | string  | sshd                             |
| pid             | string  | 1234                             |
| message         | string  | Failed password for user guest   |
| event_type      | string  | failed_login                     |
| source_ip       | string  | 198.51.100.7                     |
| ip_type         | string  | public / private                 |
| severity        | string  | LOW / MEDIUM / HIGH              |
| severity_score  | integer | 5                                |
| tags            | list    | ["external_ip", "brute_force_candidate"] |
| ingest_time     | string  | 2024-11-15T10:01:23.000Z         |
| source_type     | string  | auth_log / syslog                |
| raw             | string  | original unmodified log line     |

---

## Sample output

```json
{
  "timestamp": "2024-11-15T10:02:03",
  "host": "kali-linux",
  "process": "sshd",
  "pid": "1237",
  "message": "Failed password for invalid user guest from 198.51.100.7 port 51236 ssh2",
  "event_type": "failed_login",
  "source_ip": "198.51.100.7",
  "ip_type": "public",
  "severity": "MEDIUM",
  "severity_score": 5,
  "tags": ["external_ip", "brute_force_candidate"],
  "ingest_time": "2024-11-15T10:02:03.123456+00:00",
  "source_type": "auth_log"
}
```

---

## Querying the database

After running the pipeline, query `output/logs.db` directly:

```python
from src.storage import query_high_severity, query_brute_force, get_summary

# Get a summary of all stored events
print(get_summary('./output/logs.db'))

# Get all HIGH severity events
for row in query_high_severity('./output/logs.db'):
    print(row)

# Get all brute force candidates
for row in query_brute_force('./output/logs.db'):
    print(row)
```

---

## Threat detection

The enricher automatically detects:

| Threat                  | How                                          | Tag                     |
|-------------------------|----------------------------------------------|-------------------------|
| Brute force login       | Same IP fails login 3 or more times          | brute_force_candidate   |
| External login success  | Successful login from a public IP            | external_login_success  |
| Privileged activity     | sudo, new user creation, password change     | privileged_activity     |

---

## Roadmap

- [ ] Add Windows Event Log parser (EVTX format)
- [ ] Add Kafka output adapter for real-time streaming
- [ ] Add Sigma rule matching on parsed events
- [ ] Add a web dashboard for live event viewing
- [ ] Add unit tests with pytest

---

## Requirements

- Python 3.8+
- PyYAML
- python-dateutil

---

## License

MIT License — free to use, modify, and distribute.

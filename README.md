<p align="center">
  <img src="logo.svg" alt="SysFox AI" width="480"/>
</p>

# sysfox-ai

Diagnostic agent for the Dreamer banking POC infrastructure. Receives a question, uses LLM reasoning to run safe read-only commands across all 7 servers via SSH, and returns a structured diagnosis.

## Architecture

```
                          ┌──────────────┐
    POST /api/v1/diagnose │  sysfox-ai   │
   ─────────────────────▶ │  (FastAPI)   │
                          │              │
                          │  ┌────────┐  │    SSH     ┌──────────┐
                          │  │  LLM   │──┼──────────▶ │ poc-lb   │
                          │  │ Engine │  │            │ poc-app1 │
                          │  │        │  │            │ poc-app2 │
                          │  └────────┘  │            │ poc-rmq  │
                          │              │            │ poc-con  │
                          └──────────────┘            │ poc-pg   │
                                                      │ poc-elk  │
                                                      └──────────┘
```

**Key principle:** Diagnosis only — no remediation. The LLM can inspect but never modify.

## Quickstart

```bash
# Clone and install
cd ~/sysfox-ai
pip install -r requirements.txt

# Configure
cp .env.example .env
# Edit .env with your OpenAI API key and SSH key path

# Run
python -m sysfox_ai
```

## API Reference

### POST /api/v1/diagnose

Run a diagnostic session.

```bash
curl -X POST http://localhost:8000/api/v1/diagnose \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Why are requests to the API timing out?",
    "scope": {
      "servers": ["poc-lb", "poc-app1"],
      "components": ["nginx_lb", "app"],
      "time_range": "last 1 hour"
    },
    "max_steps": 20
  }'
```

**Response:**
```json
{
  "diagnosis_id": "uuid",
  "question": "Why are requests to the API timing out?",
  "findings": [
    {
      "severity": "HIGH",
      "component": "app",
      "server": "poc-app1",
      "summary": "FastAPI workers exhausted",
      "evidence": ["all 4 workers at 100% CPU", "request queue depth > 500"]
    }
  ],
  "affected_components": ["app", "nginx_lb"],
  "root_cause": "FastAPI workers on poc-app1 are saturated...",
  "reasoning_trace": ["Step 1: Checked nginx..."],
  "llm_model": "gpt-4o",
  "steps_taken": 5,
  "duration_seconds": 12.3
}
```

### GET /api/v1/health

Check SSH connectivity and LLM provider status.

```bash
curl http://localhost:8000/api/v1/health
```

## Configuration

All configuration via environment variables (see `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENAI_API_KEY` | - | OpenAI API key |
| `OPENAI_BASE_URL` | `https://api.openai.com/v1` | LLM API base URL |
| `OPENAI_MODEL` | `gpt-4o` | LLM model name |
| `SSH_USER` | `root` | SSH username for dreamer servers |
| `SSH_KEY_PATH` | `~/.ssh/id_rsa` | Path to SSH private key |
| `MAX_DIAGNOSTIC_STEPS` | `20` | Max tool-calling steps per diagnosis |
| `API_HOST` | `0.0.0.0` | API bind address |
| `API_PORT` | `8000` | API bind port |

## Dreamer Server Inventory

| Hostname | Role | Components |
|----------|------|------------|
| poc-lb | Load Balancer | nginx_lb |
| poc-app1 | App Server | nginx_app, app |
| poc-app2 | App Server | nginx_app, app |
| poc-rabbitmq | Message Broker | rabbitmq |
| poc-consumer | Queue Consumer | queue_consumer |
| poc-postgresql | Database | postgresql |
| poc-elk | Logging | elasticsearch, logstash, kibana |

## Safety

sysfox-ai inherits the full safety filter suite from sysadmin-ai:
- **Blocked commands** are never executed (destructive ops, credential access, privilege escalation)
- **Graylist commands** are auto-rejected in API mode (no interactive confirmation available)
- **Output redaction** strips API keys, tokens, and credentials from all tool output
- **No write tools** — the LLM has no ability to modify files or run destructive commands

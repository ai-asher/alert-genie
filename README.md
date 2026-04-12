# Alert-Genie

AI-powered alert analysis and self-healing middleware for Prometheus + Alertmanager.

Alert-Genie sits between Alertmanager and your notification channel (Lark/Feishu), automatically analyzing alerts with Claude AI and optionally executing approved remediation plans.

## Features

- **Webhook Receiver** — Receives Alertmanager webhooks with built-in deduplication and severity filtering
- **AI Analysis** — Calls Claude API with alert details, Prometheus metric trends, and service topology for root cause analysis
- **Two Modes**
  - `readonly` — Analysis results sent to Lark as interactive cards
  - `healing` — Analysis + remediation plan with approve/reject buttons in Lark
- **6-Layer Command Safety** — Prompt constraints → structural validation → anti-obfuscation → blacklist → whitelist → risk-based approval escalation
- **Approval Workflow** — Lark interactive card buttons (Approve / Reject / Modify & Approve) with auto-expiry
- **Multi-Target Execution** — K8s API (in-cluster or kubeconfig) and SSH with real-time progress updates
- **Dual Storage** — SQLite (dev) or PostgreSQL (prod), configurable via YAML
- **Self-Observability** — Prometheus `/metrics` endpoint for Alert-Genie itself

## Architecture

```
┌──────────────┐     POST /api/v1/alerts      ┌──────────────────────────────────┐
│ Alertmanager │ ───────────────────────────> │           Alert-Genie            │
└──────────────┘                              │                                  │
                                              │  ┌─────────┐   ┌─────────────┐  │
                                              │  │  Dedup   │──>│  Prometheus  │  │
                                              │  └────┬────┘   │   Fetcher    │  │
                                              │       │        └──────┬──────┘  │
                                              │       v               v         │
                                              │  ┌──────────────────────────┐   │
                                              │  │    Claude API Analyzer   │   │
                                              │  │  (Prompt + JSON Schema)  │   │
                                              │  └────────────┬────────────┘   │
                                              │               │                 │
                                              │     ┌─────────┴──────────┐      │
                                              │     │                    │      │
                                              │  ReadOnly            Healing    │
                                              │     │                    │      │
                                              │     v                    v      │
┌──────────────┐  Lark Card (analysis)        │  ┌──────┐   ┌──────────────┐   │
│   Lark Bot   │ <───────────────────────────  │  │Notify│   │Safety + Plan │   │
│              │  Lark Card (healing plan)      │  └──────┘   └──────┬──────┘   │
│   Approve ◉  │ ────────────────────────────> │                    │          │
│   Reject  ◉  │  POST /api/v1/lark/callback   │              ┌─────v─────┐    │
└──────────────┘                              │              │  Approval  │    │
                                              │              │  Manager   │    │
                                              │              └─────┬─────┘    │
                                              │                    │          │
                                              │         ┌──────────┴────────┐ │
                                              │         │     Executor      │ │
                                              │         │  K8s API / SSH    │ │
                                              │         └───────────────────┘ │
                                              └──────────────────────────────────┘
```

## Quick Start

### Prerequisites

- Go 1.22+
- Prometheus + Alertmanager
- Claude API Key ([Anthropic Console](https://console.anthropic.com/))
- Lark/Feishu Bot App (App ID + App Secret)

### Build & Run

```bash
# Clone
git clone https://github.com/laozhou333/alert-genie.git
cd alert-genie

# Build
make build

# Copy and edit config
cp configs/config.example.yaml configs/config.yaml
# Edit configs/config.yaml with your credentials

# Run
export CLAUDE_API_KEY="sk-ant-..."
export LARK_APP_ID="cli_..."
export LARK_APP_SECRET="..."
export LARK_VERIFICATION_TOKEN="..."

./bin/alert-genie -config configs/config.yaml
```

### Docker

```bash
docker build -t alert-genie:latest -f deployments/Dockerfile .

docker run -p 8080:8080 \
  -v $(pwd)/configs/config.yaml:/etc/alert-genie/config.yaml:ro \
  -e CLAUDE_API_KEY=$CLAUDE_API_KEY \
  -e LARK_APP_ID=$LARK_APP_ID \
  -e LARK_APP_SECRET=$LARK_APP_SECRET \
  -e LARK_VERIFICATION_TOKEN=$LARK_VERIFICATION_TOKEN \
  alert-genie:latest
```

### Kubernetes

```bash
# Create secrets
kubectl create secret generic alert-genie-secrets -n monitoring \
  --from-literal=claude-api-key=$CLAUDE_API_KEY \
  --from-literal=lark-app-id=$LARK_APP_ID \
  --from-literal=lark-app-secret=$LARK_APP_SECRET \
  --from-literal=lark-verification-token=$LARK_VERIFICATION_TOKEN

# Deploy
kubectl apply -f deployments/k8s/
```

## Configuration

### Alertmanager Webhook

Add Alert-Genie as a webhook receiver in your `alertmanager.yml`:

```yaml
receivers:
  - name: "alert-genie"
    webhook_configs:
      - url: "http://alert-genie:8080/api/v1/alerts"
        send_resolved: true

route:
  receiver: "alert-genie"
```

### Lark Bot Setup

1. Create a Lark/Feishu custom app at [Lark Open Platform](https://open.feishu.cn/)
2. Enable **Bot** capability
3. Set **Card Action URL** to `https://<your-domain>/api/v1/lark/callback`
4. Add the bot to your alert notification group
5. Get the group's `chat_id` and set it in config

### Key Config Sections

```yaml
mode: "readonly"           # Start with readonly, switch to healing when ready

prometheus:
  address: "http://prometheus:9090"
  query_window: 30m        # How far back to query metrics
  alert_queries:           # Per-alert PromQL templates
    HighMemoryUsage:
      - 'node_memory_MemAvailable_bytes{instance="{{.instance}}"}'

claude:
  base_url: "https://api.anthropic.com"
  api_key: "${CLAUDE_API_KEY}"
  model: "claude-sonnet-4-20250514"
  temperature: 0.1

safety:
  escalation:
    low: "auto_approve_with_notify"
    medium: "single_approval"
    high: "single_approval_with_warning"
    critical: "blocked"        # Critical commands are always blocked
```

See [`configs/config.example.yaml`](configs/config.example.yaml) for full configuration reference.

## Command Safety

Alert-Genie uses a 6-layer defense-in-depth system to prevent dangerous commands:

| Layer | Type | Description |
|-------|------|-------------|
| 1 | Prompt Constraint | LLM restricted to an allowed command vocabulary |
| 2 | Structural Validation | Reject shell operators: `\|`, `&&`, `;`, `$()`, backticks, redirects |
| 3 | Anti-Obfuscation | Reject base64, hex, octal, unicode, URL-encoded content |
| 4 | Blacklist | Regex patterns for `rm -rf`, `DROP TABLE`, `chmod 777`, `shutdown`, etc. |
| 5 | Whitelist | Commands must match a pre-defined regex pattern to be allowed |
| 6 | Risk-Based Escalation | Low=auto, Medium=approve, High=approve+warning, Critical=blocked |

### Allowed Command Vocabulary

**K8s**: `kubectl rollout restart/undo`, `kubectl scale`, `kubectl patch hpa/configmap`, `kubectl delete pod`

**SSH**: `systemctl restart/stop/start`, `journalctl`, `df`, `du`, `find -delete`, `kill`, `rm -f (single file)`, `nginx -t && nginx -s reload`

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/alerts` | Alertmanager webhook receiver |
| `POST` | `/api/v1/lark/callback` | Lark card button callback |
| `GET` | `/api/v1/alerts` | List historical alerts |
| `GET` | `/api/v1/alerts/{id}` | Get alert detail with analysis |
| `GET` | `/api/v1/approvals` | List approval records |
| `GET` | `/api/v1/executions/{id}` | Get execution logs |
| `POST` | `/api/v1/safety/validate` | Dry-run command safety check |
| `GET` | `/healthz` | Liveness probe |
| `GET` | `/readyz` | Readiness probe |
| `GET` | `/metrics` | Prometheus metrics |

## Project Structure

```
alert-genie/
├── cmd/alert-genie/main.go          # Entry point & DI wiring
├── internal/
│   ├── config/                       # YAML config loading & validation
│   ├── alert/                        # Alertmanager webhook handler & dedup
│   ├── metrics/                      # Prometheus query client
│   ├── analyzer/                     # Claude API client & prompt template
│   ├── safety/                       # 6-layer command safety validator
│   ├── approval/                     # Approval state machine
│   ├── executor/                     # K8s & SSH command executors
│   ├── notifier/                     # Lark card builder & callback handler
│   ├── pipeline/                     # Core orchestrator
│   ├── store/                        # SQLite & PostgreSQL persistence
│   └── topology/                     # Service topology provider
├── configs/                          # Example configuration files
└── deployments/                      # Dockerfile, docker-compose, K8s manifests
```

## Tech Stack

- **Language**: Go 1.22
- **HTTP Router**: [chi](https://github.com/go-chi/chi)
- **K8s Client**: kubectl (via exec)
- **SSH**: golang.org/x/crypto/ssh
- **Database**: SQLite (mattn/go-sqlite3) / PostgreSQL (lib/pq)
- **LLM**: Claude API (direct HTTP, no SDK dependency)
- **Notification**: Lark Open API (direct HTTP, no SDK dependency)

## License

MIT

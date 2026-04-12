<p align="center">
  <a href="README.md">English</a> | <b>中文</b>
</p>

# Alert-Genie

基于 AI 的告警智能分析与自愈中间件，适用于 Prometheus + Alertmanager 技术栈。

Alert-Genie 部署在 Alertmanager 和通知渠道（飞书/Lark）之间，自动通过 Claude AI 分析告警根因，并可在审批后执行自愈方案。

## 功能特性

- **Webhook 接收** — 接收 Alertmanager Webhook，内置指纹去重和告警等级过滤
- **AI 智能分析** — 调用 Claude API，结合告警详情、Prometheus 指标趋势、服务拓扑进行根因分析
- **双模式运行**
  - `readonly` — 仅分析，结果以飞书交互卡片发送
  - `healing` — 分析 + 自愈方案，飞书卡片内一键审批/驳回
- **6 层命令安全防护** — Prompt 约束 → 结构校验 → 反混淆 → 黑名单 → 白名单 → 风险分级审批
- **审批工作流** — 飞书交互卡片按钮（批准 / 驳回 / 修改后批准），支持自动过期
- **多目标执行** — 支持 K8s API（集群内/kubeconfig）和 SSH，实时推送执行进度
- **双存储引擎** — SQLite（开发）或 PostgreSQL（生产），YAML 配置切换
- **自身可观测** — 内置 Prometheus `/metrics` 端点

## 系统架构

```
┌──────────────┐     POST /api/v1/alerts      ┌──────────────────────────────────┐
│ Alertmanager │ ───────────────────────────> │           Alert-Genie            │
└──────────────┘                              │                                  │
                                              │  ┌─────────┐   ┌─────────────┐  │
                                              │  │  去重过滤  │──>│ Prometheus  │  │
                                              │  └────┬────┘   │   指标采集    │  │
                                              │       │        └──────┬──────┘  │
                                              │       v               v         │
                                              │  ┌──────────────────────────┐   │
                                              │  │    Claude API 智能分析    │   │
                                              │  │  (Prompt + JSON Schema)  │   │
                                              │  └────────────┬────────────┘   │
                                              │               │                 │
                                              │     ┌─────────┴──────────┐      │
                                              │     │                    │      │
                                              │  只读模式            自愈模式    │
                                              │     │                    │      │
                                              │     v                    v      │
┌──────────────┐  飞书卡片（分析结果）          │  ┌──────┐   ┌──────────────┐   │
│   飞书 Bot   │ <───────────────────────────  │  │ 通知  │   │ 安全校验+方案 │   │
│              │  飞书卡片（自愈方案）           │  └──────┘   └──────┬──────┘   │
│   批准  ◉    │ ────────────────────────────> │                    │          │
│   驳回  ◉    │  POST /api/v1/lark/callback   │              ┌─────v─────┐    │
└──────────────┘                              │              │  审批管理   │    │
                                              │              └─────┬─────┘    │
                                              │                    │          │
                                              │         ┌──────────┴────────┐ │
                                              │         │     执行引擎      │ │
                                              │         │  K8s API / SSH    │ │
                                              │         └───────────────────┘ │
                                              └──────────────────────────────────┘
```

## 快速开始

### 前置条件

- Go 1.22+
- Prometheus + Alertmanager
- Claude API Key（[Anthropic 控制台](https://console.anthropic.com/)）
- 飞书/Lark 自建应用（App ID + App Secret）

### 编译运行

```bash
# 克隆仓库
git clone https://github.com/ai-asher/alert-genie.git
cd alert-genie

# 编译
make build

# 复制并编辑配置文件
cp configs/config.example.yaml configs/config.yaml
# 编辑 configs/config.yaml 填入你的凭证

# 设置环境变量并运行
export CLAUDE_API_KEY="sk-ant-..."
export LARK_APP_ID="cli_..."
export LARK_APP_SECRET="..."
export LARK_VERIFICATION_TOKEN="..."

./bin/alert-genie -config configs/config.yaml
```

### Docker 部署

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

### Kubernetes 部署

```bash
# 创建 Secret
kubectl create secret generic alert-genie-secrets -n monitoring \
  --from-literal=claude-api-key=$CLAUDE_API_KEY \
  --from-literal=lark-app-id=$LARK_APP_ID \
  --from-literal=lark-app-secret=$LARK_APP_SECRET \
  --from-literal=lark-verification-token=$LARK_VERIFICATION_TOKEN

# 部署
kubectl apply -f deployments/k8s/
```

## 配置说明

### Alertmanager Webhook 配置

在 `alertmanager.yml` 中添加 Alert-Genie 作为 webhook 接收端：

```yaml
receivers:
  - name: "alert-genie"
    webhook_configs:
      - url: "http://alert-genie:8080/api/v1/alerts"
        send_resolved: true

route:
  receiver: "alert-genie"
```

### 飞书 Bot 配置

1. 在[飞书开放平台](https://open.feishu.cn/)创建自建应用
2. 开启 **机器人** 能力
3. 设置 **消息卡片请求网址** 为 `https://<你的域名>/api/v1/lark/callback`
4. 将机器人添加到告警通知群
5. 获取群的 `chat_id` 并填入配置文件

### 核心配置项

```yaml
mode: "readonly"           # 先用 readonly 模式验证，就绪后切换到 healing

prometheus:
  address: "http://prometheus:9090"
  query_window: 30m        # 告警触发时回溯查询的时间窗口
  alert_queries:           # 按告警名称配置的 PromQL 模板
    HighMemoryUsage:
      - 'node_memory_MemAvailable_bytes{instance="{{.instance}}"}'

claude:
  base_url: "https://api.anthropic.com"
  api_key: "${CLAUDE_API_KEY}"
  model: "claude-sonnet-4-20250514"
  temperature: 0.1         # 低温度确保分析结果的确定性

safety:
  escalation:
    low: "auto_approve_with_notify"      # 低风险：自动通过，仅通知
    medium: "single_approval"            # 中风险：需要单人审批
    high: "single_approval_with_warning" # 高风险：审批 + 风险警告
    critical: "blocked"                  # 严重：直接拦截
```

完整配置参考 [`configs/config.example.yaml`](configs/config.example.yaml)。

## 命令安全体系

Alert-Genie 采用 6 层纵深防御体系，防止 AI 生成的危险命令被执行：

| 层级 | 类型 | 说明 |
|------|------|------|
| 1 | Prompt 约束 | 在 Prompt 中限定 LLM 只能使用预定义的命令词汇表 |
| 2 | 结构校验 | 拒绝包含 Shell 操作符的命令：`\|`、`&&`、`;`、`$()`、反引号、重定向 |
| 3 | 反混淆检测 | 拒绝 base64、十六进制、八进制、Unicode、URL 编码内容 |
| 4 | 黑名单拦截 | 正则匹配 `rm -rf`、`DROP TABLE`、`chmod 777`、`shutdown` 等危险模式 |
| 5 | 白名单放行 | 命令必须匹配预定义的正则白名单才能通过 |
| 6 | 风险分级审批 | 低风险=自动通过、中风险=审批、高风险=审批+警告、严重=直接拦截 |

### 允许的命令词汇表

**K8s 命令**：`kubectl rollout restart/undo`、`kubectl scale`、`kubectl patch hpa/configmap`、`kubectl delete pod`

**SSH 命令**：`systemctl restart/stop/start`、`journalctl`、`df`、`du`、`find -delete`、`kill`、`rm -f（仅限单文件）`、`nginx -t && nginx -s reload`

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| `POST` | `/api/v1/alerts` | Alertmanager Webhook 接收端 |
| `POST` | `/api/v1/lark/callback` | 飞书卡片按钮回调 |
| `GET` | `/api/v1/alerts` | 查询历史告警列表 |
| `GET` | `/api/v1/alerts/{id}` | 查询告警详情（含分析结果） |
| `GET` | `/api/v1/approvals` | 查询审批记录 |
| `GET` | `/api/v1/executions/{id}` | 查询执行日志 |
| `POST` | `/api/v1/safety/validate` | 命令安全校验（Dry-run） |
| `GET` | `/healthz` | 存活探针 |
| `GET` | `/readyz` | 就绪探针 |
| `GET` | `/metrics` | Prometheus 指标端点 |

## 项目结构

```
alert-genie/
├── cmd/alert-genie/main.go          # 入口 & 依赖注入
├── internal/
│   ├── config/                       # YAML 配置加载与校验
│   ├── alert/                        # Alertmanager Webhook 处理 & 去重
│   ├── metrics/                      # Prometheus 查询客户端
│   ├── analyzer/                     # Claude API 客户端 & Prompt 模板
│   ├── safety/                       # 6 层命令安全校验器
│   ├── approval/                     # 审批状态机
│   ├── executor/                     # K8s & SSH 命令执行器
│   ├── notifier/                     # 飞书卡片构建 & 回调处理
│   ├── pipeline/                     # 核心编排器
│   ├── store/                        # SQLite & PostgreSQL 持久层
│   └── topology/                     # 服务拓扑提供者
├── configs/                          # 示例配置文件
└── deployments/                      # Dockerfile、docker-compose、K8s 清单
```

## 技术栈

- **语言**：Go 1.22
- **HTTP 路由**：[chi](https://github.com/go-chi/chi)
- **K8s 操作**：kubectl（通过 exec 调用）
- **SSH**：golang.org/x/crypto/ssh
- **数据库**：SQLite (mattn/go-sqlite3) / PostgreSQL (lib/pq)
- **LLM**：Claude API（直接 HTTP 调用，无 SDK 依赖）
- **通知**：飞书开放 API（直接 HTTP 调用，无 SDK 依赖）

## License

MIT

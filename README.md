# AgentDockControl / AgentDockClient

> 远程 AI Agent 管理系统 — 服务端 + 客户端 CLI

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688)](https://fastapi.tiangolo.com)
[![Node.js](https://img.shields.io/badge/Node.js-22%2B-339933)](https://nodejs.org)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

---

## 目录

- [项目简介](#项目简介)
- [架构](#架构)
- [功能特性](#功能特性)
- [快速开始](#快速开始)
- [API 参考](#api-参考)
- [配置](#配置)
- [开发指南](#开发指南)
- [部署](#部署)

---

## 项目简介

AgentDock 是一套远程 AI Agent 管理方案，包含：

| 组件 | 技术栈 | 用途 |
|------|--------|------|
| **AgentDockControl** (服务端) | Python FastAPI + python-socketio | 配对认证、会话管理、实时信令、Web 控制台 |
| **AgentDockClient** (客户端 CLI) | Node.js + tweetnacl | 连接到服务端，管理本地 AI Agent |

系统支持多设备同时连接、实时 Web UI 操控、权限审批、定时任务、用量统计等功能。

---

## 架构

```
┌──────────────────────────────────────────────────┐
│                  Web 控制台                       │
│          (HTML/CSS/JS + Socket.IO)               │
├──────────────────────────────────────────────────┤
│              AgentDockControl 服务端              │
│  ┌──────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ FastAPI  │  │ Socket.IO    │  │ SQLite     │ │
│  │ (REST)   │  │ (WebSocket)  │  │ (Storage)  │ │
│  └────┬─────┘  └──────┬───────┘  └─────┬──────┘ │
│       │               │                │        │
│  ┌────┴─────┐  ┌──────┴───────┐  ┌─────┴──────┐ │
│  │ 配对/认证 │  │ 实时信令     │  │ 持久化     │ │
│  │ 机器管理  │  │ 会话同步     │  │ 任务调度   │ │
│  │ 会话 CRUD │  │ 权限审批     │  │ 用量统计   │ │
│  └──────────┘  └──────────────┘  └────────────┘ │
├──────────────────────────────────────────────────┤
│               AgentDockClient CLI                 │
│  ┌──────────┐  ┌──────────────┐  ┌────────────┐ │
│  │ 配对模块 │  │ Agent 运行器 │  │ NaCl 加密  │ │
│  │ (pair.js)│  │ (run.js)     │  │ (util.js)  │ │
│  └──────────┘  └──────────────┘  └────────────┘ │
└──────────────────────────────────────────────────┘
```

### 通信流程

1. **配对：** 客户端发起配对请求 → 服务端生成 PIN + QR → 用户确认 → 密钥交换完成
2. **认证：** 客户端使用 NaCl Box 加密认证数据 → 服务端 Ed25519 验签 → 颁发 Token
3. **会话：** 客户端通过 WebSocket 连接 → 注册设备 → 创建/管理 AI Agent 会话
4. **控制：** Web 控制台通过服务端向客户端发送指令 → 客户端执行并返回结果

---

## 功能特性

### 服务端 (AgentDockControl)

| 功能 | 说明 |
|------|------|
| **设备配对** | PIN + QR 码配对，NaCl Box 加密密钥交换 |
| **设备管理** | 注册、心跳检测、上下线广播 |
| **会话管理** | 创建/监控/控制/停止 AI Agent 会话 |
| **实时信令** | Socket.IO WebSocket 全双工通信 |
| **权限控制** | 细粒度审批模型，支持 Web UI 一键审批 |
| **定时任务** | Cron 表达式调度，任务状态跟踪 |
| **用量统计** | 调用次数、耗时、会话时长统计 |
| **Web 控制台** | 内置管理界面，设备/会话/统计面板 |

### 客户端 (AgentDockClient)

| 功能 | 说明 |
|------|------|
| **配对** | CLI 交互式配对流程 |
| **Agent 管理** | 启动/监控/停止本地 AI Agent |
| **会话同步** | 支持断线重连，历史同步 |
| **加密通信** | tweetnacl NaCl Box 端到端加密 |

---

## 快速开始

### 前置依赖

- Python 3.10+
- Node.js 22+
- pip / npm

### 1. 启动服务端

```bash
# 进入服务端目录
cd server

# 安装依赖
pip install -r requirements.txt

# 启动服务
python main.py
```

服务端默认监听 `http://0.0.0.0:8080`。

启动后打开 `http://localhost:8080` 即可访问 Web 控制台。

### 2. 运行客户端

```bash
# 进入客户端目录
cd adclient

# 安装依赖
npm install

# 查看帮助
node bin/cli.js --help

# 启动配对流程
node bin/cli.js pair

# 运行 AI Agent
node bin/cli.js run
```

### 端到端示例

```bash
# 终端 1：启动服务端
cd server && python main.py

# 终端 2：客户端配对
cd adclient && node bin/cli.js pair
# → 显示 QR 码 + PIN

# 浏览器打开 http://localhost:8080
# → 在 Web 控制台输入 PIN 完成配对

# 配对完成后
node bin/cli.js run --agent hermes --prompt "帮我检查系统状态"
```

---

## API 参考

### REST API

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/v1/pair/init` | 发起配对请求 |
| POST | `/v1/pair/approve` | 审批配对 |
| POST | `/v1/auth/challenge` | 获取认证挑战 |
| POST | `/v1/auth/verify` | 提交认证签名 |
| GET | `/v1/devices` | 获取设备列表 |
| GET | `/v1/sessions` | 获取会话列表 |
| POST | `/v1/sessions/{id}/answer` | 回答 Agent 提问 |
| POST | `/v1/sessions/{id}/permission` | 审批/拒绝权限 |
| POST | `/v1/sessions/{id}/abort` | 中止当前执行 |
| POST | `/v1/sessions/{id}/stop` | 停止会话 |
| POST | `/v1/sessions/{id}/switch-mode` | 切换权限模式 |
| GET | `/v1/stats` | 获取用量统计 |

### WebSocket (Socket.IO)

路径 `/v1/updates`，支持以下事件：

| 事件方向 | 事件名 | 说明 |
|----------|--------|------|
| 服务端→客户端 | `machine-status-update` | 机器上下线通知 |
| 服务端→客户端 | `session-create` | 新会话通知 |
| 服务端→客户端 | `session-update` | 会话状态变更 |
| 服务端→客户端 | `permission-resolved` | 权限审批结果 |
| 服务端→客户端 | `ephemeral` | 实时执行输出 |
| 服务端→客户端 | `telemetry-report` | 遥测数据推送 |
| 服务端→客户端 | `usage-report` | 用量报告 |
| 客户端→服务端 | `register-history-sessions` | 历史会话注册 |
| 客户端→服务端 | `update-sync-status` | 同步状态更新 |
| 客户端→服务端 | `machine-status-update` | 机器状态上报 |

---

## 配置

### 服务端配置

通过环境变量或 `server/config.py` 配置：

```python
# server/config.py
host: str = "0.0.0.0"
port: int = 8080
db_path: str = "agentdock.db"  # SQLite 数据库路径
pairing_timeout: int = 300     # 配对超时（秒）
session_timeout: int = 3600   # 会话超时（秒）
```

### 客户端配置

```bash
# 环境变量
export AGENTDOCK_SERVER_URL=http://192.168.1.100:8080
export AGENTDOCK_TOKEN=your_auth_token
```

---

## 项目结构

```
AgentDock/
├── server/                    # 服务端
│   ├── main.py               # 应用入口
│   ├── server.py              # FastAPI + Socket.IO 核心
│   ├── rpc_handler.py         # RPC 路由分发
│   ├── storage.py             # SQLite 存储层
│   ├── crypto.py              # NaCl + AES 加密
│   ├── config.py              # 配置管理
│   ├── hardening.py           # 熔断器/重连
│   ├── scheduler.py           # 定时任务引擎
│   ├── approve_pairing.py     # 配对审批 CLI
│   ├── requirements.txt       # Python 依赖
│   ├── static/                # Web 管理界面
│   │   ├── index.html         # 控制台页面
│   │   ├── js/app.js          # 前端逻辑
│   │   ├── css/style.css      # 样式
│   │   └── socket.io.min.js   # Socket.IO 客户端
│   └── test_*.py              # 测试
├── adclient/                  # 客户端
│   ├── package.json           # Node.js 依赖
│   ├── bin/cli.js             # CLI 入口
│   └── lib/
│       ├── pair.js            # 配对逻辑
│       ├── run.js             # Agent 运行管理
│       └── util.js            # 工具函数
└── README.md                  # 本文件
```

---

## 开发指南

### 运行测试

```bash
cd server

# 端到端测试
python test_e2e.py

# 配对流程测试
python test_pairing_flow.py
```

### 代码风格

- Python: PEP 8, 使用 `black` + `isort`
- JavaScript: StandardJS
- 提交信息: `类型: 简短描述`

### 开发模式

```bash
# 服务端热重载
cd server && uvicorn main:app --reload --host 0.0.0.0 --port 8080
```

---

## 部署

### Docker

```dockerfile
# 服务端 Dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY server/ .
RUN pip install -r requirements.txt
EXPOSE 8080
CMD ["python", "main.py"]
```

### Systemd

```ini
[Unit]
Description=AgentDockControl Server
After=network.target

[Service]
Type=simple
User=youruser
WorkingDirectory=/opt/agentdock/server
ExecStart=/usr/bin/python3 main.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

---

## 技术栈

### 服务端
- **Web 框架：** FastAPI 0.115+
- **实时通信：** python-socketio 5.x + python-engineio
- **加密：** PyNaCl (NaCl Box) + cryptography (AES-256-GCM)
- **存储：** SQLite (aiosqlite)
- **运行：** uvicorn

### 客户端
- **运行时：** Node.js 22+
- **加密：** tweetnacl + tweetnacl-util
- **通信：** WebSocket (原生)

### 前端
- **技术：** 原生 HTML/CSS/JS
- **实时通信：** Socket.IO Client v2.x
- **UI：** 响应式设计，深色主题

---

## 许可证

MIT License — 详见 [LICENSE](LICENSE) 文件。

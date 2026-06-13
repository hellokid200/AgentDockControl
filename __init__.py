"""
AgentDockControl 服务端包。

提供远程 AI Agent 管理的完整服务端实现：
  - 设备配对与认证
  - 会话管理
  - 实时信令
  - 定时任务
  - 用量统计
"""

- HTTP REST API for pairing, authentication, session management, and stats
- Socket.IO signaling for real-time communication with daemon machines
- SQLite-based persistence for pairing requests, machines, sessions, and messages
- NaCl box + AES-256-GCM encryption for end-to-end data protection
- Scheduled task engine for cron-based agent session automation
- Circuit breakers and exponential backoff for system resilience

Protocol version: 1
"""

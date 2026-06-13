"""
服务端配置管理。

提供单例 Settings 数据类，从环境变量加载配置，
包含适用于本地开发的默认值。
"""
with sensible defaults suitable for local development.
"""

import os
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Settings:
    """Server-wide configuration, sourced from environment variables.

    Attributes:
        host: Bind address for the HTTP server (default: 0.0.0.0).
        port: Listen port, overridable via PORT env var (default: 8080).
        db_path: Path to the SQLite database file.
        data_dir: Directory for runtime data files.
        socket_path: Socket.IO path for real-time signaling.
        protocol_version: Wire protocol version (currently 1).
        pairing_pin_ttl: Seconds before a pairing PIN expires (default: 10 min).
        pairing_pin_length: Number of digits in the pairing PIN.
        pairing_poll_max_attempts: Max polls before giving up.
        pairing_poll_interval: Seconds between pairing status polls.
        auth_challenge_ttl: Seconds before an auth challenge expires.
        token_ttl: Lifetime of issued auth tokens (default: 7 days).
        machine_heartbeat_timeout: Seconds without heartbeat before marking dead.
        cors_origins: Allowed CORS origins (default: all origins).
        web_url: Override for the Web UI URL used in pairing URLs.
    """
    host: str = "0.0.0.0"
    port: int = int(os.getenv("PORT", "8080"))
    db_path: str = os.getenv(
        "DB_PATH",
        os.path.join(os.path.dirname(__file__), "agentdock.db"),
    )
    data_dir: str = os.getenv(
        "DATA_DIR",
        os.path.join(os.path.dirname(__file__), "data"),
    )

    # Socket.IO path — must match what the SDK client expects
    socket_path: str = "/v1/updates"

    # Protocol version required for all connecting clients
    protocol_version: int = 1

    # Pairing configuration
    pairing_pin_ttl: int = 600           # 10 minutes
    pairing_pin_length: int = 6
    pairing_poll_max_attempts: int = 300
    pairing_poll_interval: float = 1.0

    # Authentication configuration
    auth_challenge_ttl: int = 60         # 1 minute
    token_ttl: int = 86400 * 7           # 7 days

    # Machine health: heartbeat every 30s, 3 missed = dead
    machine_heartbeat_timeout: int = 90

    # Cross-Origin Resource Sharing
    cors_origins: list[str] = field(default_factory=lambda: ["*"])

    # Optional override for Web UI base URL (pairing URL generation)
    web_url: Optional[str] = os.getenv("AGENTDOCK_WEB_URL")


# Module-level singleton — imported by all other modules
settings = Settings()

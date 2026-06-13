"""
AgentDock 协议服务端入口。

通过 uvicorn 启动 ASGI 应用 (FastAPI + python-socketio)。
"""
Starts the ASGI application (FastAPI + python-socketio) via uvicorn with
configurable host, port, database path, and hot-reload support.

Usage:
    python main.py                    # Start on default port 8080
    python main.py --port 9090        # Custom port
    python main.py --host 127.0.0.1   # Local only
    python main.py --reload           # Auto-reload on code changes

Environment:
    PORT=8080
    DB_PATH=/path/to/agentdock.db
    AGENTDOCK_WEB_URL=https://my-web-ui.com
"""

import argparse
import logging
import os
import sys

import uvicorn

from config import settings

# Configure root logger with timestamp, level, and module name
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)


def main():
    """Parse CLI args, apply overrides to settings, and start the uvicorn server."""
    parser = argparse.ArgumentParser(description="AgentDock Protocol Server")
    parser.add_argument("--host", default=None, help="Bind address")
    parser.add_argument("--port", type=int, default=None, help="Listen port")
    parser.add_argument("--db", default=None, help="SQLite database path")
    parser.add_argument("--reload", action="store_true", help="Auto-reload on code changes")
    args = parser.parse_args()

    # Apply CLI argument overrides to the shared settings singleton
    if args.host:
        settings.host = args.host
    if args.port:
        settings.port = args.port
    if args.db:
        settings.db_path = args.db

    # Import the mounted Socket.IO ASGI app (delayed import to avoid circular deps)
    from server import sio_asgi_app

    # Configure and start uvicorn with the combined ASGI app
    config = uvicorn.Config(
        sio_asgi_app,
        host=settings.host,
        port=settings.port,
        log_level="info",
        reload=args.reload,
    )
    server = uvicorn.Server(config)

    logger = logging.getLogger("agentdock")
    logger.info(
        f"AgentDock server listening on http://{settings.host}:{settings.port}"
    )
    server.run()


if __name__ == "__main__":
    main()

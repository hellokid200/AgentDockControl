#!/usr/bin/env python3
"""
End-to-end test: pairing flow + Socket.IO connection + machine registration.

Exercises the full lifecycle:
  1. Health check
  2. Pairing request and respond
  3. Token-based authentication
  4. Socket.IO connection with machine registration
  5. Heartbeat, session creation, message send/retrieve
  6. Session end and REST verification
"""

import asyncio
import json
import sys
import time
import uuid

import socketio

#: Base URL of the running server instance
SERVER = "http://localhost:8084"
#: Test public key (base64-encoded dummy)
PUBLIC_KEY = "dGVzdHB1YmtleXlvbG9sb2xsb2xsb2xsb2xsb2xsb2xsb2w"


async def test_full_flow():
    """Execute the full end-to-end test sequence."""
    print("=" * 60)
    print("AgentDock Server — End-to-End Test")
    print("=" * 60)

    import httpx

    async with httpx.AsyncClient(base_url=SERVER) as h:
        # ── 1. Health check ──
        r = await h.get("/v1/health")
        assert r.status_code == 200, f"Health: {r.status_code}"
        data = r.json()
        assert data["ok"]
        assert data["protocolVersion"] == 1
        print("✅  Health check")

        # ── 2. Pairing request ──
        r = await h.post(
            "/v1/pairing/request",
            json={"publicKey": PUBLIC_KEY},
        )
        assert r.status_code == 200, f"Pairing request: {r.status_code}"
        data = r.json()
        assert "pin" in data
        assert len(data["pin"]) == 6
        assert "pairingUrl" in data
        print(f"✅  Pairing request — PIN={data['pin']}")

        # ── 3. Pairing status (pending) ──
        r = await h.get(f"/v1/pairing/status/{PUBLIC_KEY}")
        assert r.status_code == 200
        data = r.json()
        assert data["state"] == "pending"
        print(f"✅  Pairing status: {data['state']}")

        # ── 4. Web responds to pairing ──
        encrypted_payload = "dGVzdF9lbmNyeXB0ZWRfcGF5bG9hZA=="
        r = await h.post(
            "/v1/pairing/respond",
            json={
                "publicKey": PUBLIC_KEY,
                "encryptedPayload": encrypted_payload,
            },
        )
        assert r.status_code == 200
        data = r.json()
        assert data["ok"]
        TOKEN = data["token"]
        assert TOKEN.startswith("ad_")
        print(f"✅  Web respond — token={TOKEN[:16]}...")

        # ── 5. Pairing status (authorized) ──
        r = await h.get(f"/v1/pairing/status/{PUBLIC_KEY}")
        assert r.status_code == 200
        data = r.json()
        assert data["state"] == "authorized"
        assert data["encryptedPayload"] == encrypted_payload
        assert data["token"] == TOKEN
        print(f"✅  Pairing status: {data['state']}")

        # ── 6. Auth (key-based) ──
        r = await h.post("/v1/auth", json={"key": PUBLIC_KEY})
        assert r.status_code == 200
        data = r.json()
        assert data["token"] == TOKEN
        print("✅  Auth (key-based)")

    # ── 7. Socket.IO connect + machine register ──
    print("\n--- Socket.IO test ---")
    sio_client = socketio.AsyncClient()
    connected = asyncio.Event()
    disconnected = asyncio.Event()

    @sio_client.on("connect")
    def on_connect():
        print("✅  Socket.IO connected")
        connected.set()

    @sio_client.on("disconnect")
    def on_disconnect():
        print("Socket.IO disconnected")
        disconnected.set()

    @sio_client.on("rpc-request")
    def on_rpc_request(data):
        print(f"📩 RPC request received: {data}")

    # Connect with auth token and machine ID
    machine_id = f"m_test_{uuid.uuid4().hex[:8]}"
    await sio_client.connect(
        SERVER,
        socketio_path="/v1/updates",
        auth={
            "token": TOKEN,
            "machineId": machine_id,
            "clientType": "machine-scoped",
            "protocolVersion": 1,
        },
        transports=["websocket"],
    )
    await asyncio.wait_for(connected.wait(), timeout=5)

    # Register machine metadata
    result = await sio_client.call("machine-register", {
        "id": machine_id,
        "hostname": "test-host",
        "platform": "linux",
        "arch": "x86_64",
        "availableAgents": ["claude", "openclaw"],
        "daemonVersion": "0.0.47",
    })
    assert result["ok"]
    print(f"✅  Machine registered: {machine_id}")

    # Send heartbeat
    result = await sio_client.call("machine-heartbeat", {})
    assert result["ok"]
    print("✅  Machine heartbeat")

    # Register RPC methods
    for method in ["get-machine-info", "get-agent-settings", "check-path"]:
        result = await sio_client.call("rpc-register", {"method": method})
        assert result["ok"]
    print("✅  RPC methods registered")

    # Create a session
    session_id = f"s_test_{uuid.uuid4().hex[:8]}"
    result = await sio_client.call("session-create", {
        "tag": "test-session",
        "metadata": {"cwd": "/home/test"},
        "source": "managed",
    })
    assert result["ok"]
    created_sid = result["sessionId"]
    print(f"✅  Session created: {created_sid}")

    # Keep session alive
    result = await sio_client.call("session-alive", {
        "sessionId": created_sid,
    })
    assert result["ok"]
    print("✅  Session alive")

    # Send an encrypted message
    result = await sio_client.call("message", {
        "sessionId": created_sid,
        "localId": "msg_001",
        "content": {"t": "encrypted", "c": "dGVzdF9jaXBoZXJ0ZXh0"},
    })
    assert result["ok"]
    print(f"✅  Message sent (seq={result.get('seq', '?')})")

    # Retrieve messages
    result = await sio_client.call("get-messages", {
        "sessionId": created_sid,
        "limit": 10,
    })
    assert result.get("total", 0) >= 1
    print(f"✅  Messages retrieved: {result['total']} total")

    # End the session
    result = await sio_client.call("session-end", {
        "sessionId": created_sid,
        "summary": {"status": "completed"},
    })
    assert result["ok"]
    print("✅  Session ended")

    # Verify session status via REST
    async with httpx.AsyncClient(base_url=SERVER) as h:
        r = await h.get(
            f"/v1/sessions/{created_sid}",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        data = r.json()
        assert data["session"]["status"] == "ended"
        print(f"✅  Session status verified: {data['session']['status']}")

    # List machines via REST
    async with httpx.AsyncClient(base_url=SERVER) as h:
        r = await h.get(
            "/v1/machines",
            headers={"Authorization": f"Bearer {TOKEN}"},
        )
        machines = r.json()["machines"]
        assert len(machines) >= 1
        print(f"✅  Machines listed: {len(machines)}")

    # Disconnect
    await sio_client.disconnect()
    print("✅  Socket.IO disconnected")

    print("\n" + "=" * 60)
    print("ALL TESTS PASSED 🎉")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(test_full_flow())

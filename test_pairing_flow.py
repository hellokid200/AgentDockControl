#!/usr/bin/env python3
"""
Test the full pairing flow of the AgentDock server.

Exercises:
  1. Health check
  2. Pairing request creation
  3. Pairing status polling
  4. Web UI respond (authorize)
  5. Authenticated endpoint access with token
"""

import json
import urllib.request
import urllib.error
import sys

#: Base URL of the running server instance
BASE = "http://localhost:8080"


def req(method, path, data=None, token=None):
    """Make an HTTP request and return the parsed JSON response.

    Args:
        method: HTTP method string.
        path: URL path (appended to BASE).
        data: Optional dict to send as JSON body.
        token: Optional Bearer token for Authorization header.

    Returns:
        Parsed JSON response dict.
    """
    url = BASE + path
    body = json.dumps(data).encode() if data else None
    h = {"Content-Type": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    r = urllib.request.Request(url, data=body, headers=h, method=method)
    try:
        with urllib.request.urlopen(r) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        return json.loads(e.read())


# 1. Health check
print("=== 1. Health ===")
print(json.dumps(req("GET", "/v1/health"), indent=2))

# 2. Pairing request
print("\n=== 2. Pairing Request ===")
pair = req("POST", "/v1/pairing/request", {
    "publicKey": "test123",
    "label": "test-device",
    "pin": "123456",
})
print(json.dumps(pair, indent=2))

# 3. Check pairing status
pk = pair.get("publicKey", "test123")
print(f"\n=== 3. Pairing Status (key={pk}) ===")
print(json.dumps(req("GET", f"/v1/pairing/status/{pk}"), indent=2))

# 4. Respond (simulate Web UI confirming the pairing)
print(f"\n=== 4. Pairing Respond ===")
resp = req("POST", "/v1/pairing/respond", {
    "publicKey": pk,
    "encryptedPayload": "test_encrypted_payload",
})
print(json.dumps(resp, indent=2))

# 5. Test authenticated endpoints with the received token
token = resp.get("token", "")
if token:
    print(f"\n=== 5. Authenticated Endpoints (token={token[:20]}...) ===")
    print("Sessions:", json.dumps(req("GET", "/v1/sessions", token=token), indent=2)[:100])
    print("Machines:", json.dumps(req("GET", "/v1/machines", token=token), indent=2)[:100])
    print("Stats:", json.dumps(req("GET", "/v1/stats", token=token), indent=2)[:100])
    print("CB:", json.dumps(req("GET", "/v1/circuit-breakers", token=token), indent=2)[:100])
else:
    print("\nNo token received — auth may use different flow")
    print("Checking config...")
    import os
    cwd = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, cwd)
    try:
        from config import settings
        print(f"Auth mode: {settings.auth_mode}")
    except Exception:
        print("Could not load config")

print("\n=== Done ===")

"""
CLI 工具：审批服务端上的待处理配对请求。

用法：
    python approve_pairing.py <pairing_code>
"""
Usage:
    python approve_pairing.py

This script:
  1. Queries a specific pairing request status.
  2. Sends a respond request with an encrypted payload to authorize the pairing.

The public key and endpoints are hardcoded for development/testing.
"""

import json
import urllib.request

# 1. Find pending pairing requests — query status of a known public key
r = urllib.request.Request(
    "http://localhost:8080/v1/pairing/status/"
    "V8sIuKkdNtDTZq9YwoDeIWXHLranDkGBVIfptsLB13w"
)
resp = urllib.request.urlopen(r)
print("Status:", resp.read().decode())

# 2. Respond to pairing — authorize the key with an encrypted payload
data = json.dumps({
    "publicKey": "V8sIuKkdNtDTZq9YwoDeIWXHLranDkGBVIfptsLB13w",
    "encryptedPayload": "confirmed",
}).encode()
r2 = urllib.request.Request(
    "http://localhost:8080/v1/pairing/respond",
    data=data,
    headers={"Content-Type": "application/json"},
    method="POST",
)
resp2 = urllib.request.urlopen(r2)
print("Respond:", resp2.read().decode())

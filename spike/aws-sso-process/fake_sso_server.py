#!/usr/bin/env python3
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
"""Stand-ins for AWS IAM Identity Center's two APIs, so the spike can drive
the real AWS CLI's SSO flows without an AWS account.

- SSO OIDC (oidc.<region>.amazonaws.com): RegisterClient, the device flow's
  StartDeviceAuthorization, and CreateToken for both the device_code grant
  (`aws sso login --use-device-code`) and the refresh_token grant (the
  silent refresh botocore runs when the access token nears expiry).
- SSO portal (portal.sso.<region>.amazonaws.com): GetRoleCredentials, the
  call that turns the SSO access token into role credentials.

The CLI is pointed here with AWS_ENDPOINT_URL_SSO_OIDC and AWS_ENDPOINT_URL_SSO.
Every request is appended to LOG as one JSON line. ROTATE=1 returns a new
refresh token on every refresh (what IAM Identity Center does), TTL sets the
access token's lifetime in seconds.

  PORT=8780 LOG=req.jsonl ROTATE=1 TTL=3600 python3 fake_sso_server.py
"""
import json
import os
import sys
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8780"))
LOG = os.environ.get("LOG", "req.jsonl")
ROTATE = os.environ.get("ROTATE", "1") == "1"
TTL = int(os.environ.get("TTL", "3600"))
n = 0


def log(entry):
    with open(LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


class Handler(BaseHTTPRequestHandler):
    def reply(self, body, status=200):
        out = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)

    def body(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", 0)) or 0)
        try:
            return json.loads(raw or b"{}")
        except ValueError:
            return {}

    def do_POST(self):
        global n
        n += 1
        b = self.body()
        path = self.path.split("?")[0]
        if path == "/client/register":
            log({"n": n, "op": "RegisterClient"})
            return self.reply({
                "clientId": "fake-client-id", "clientSecret": "fake-client-secret",
                "clientIdIssuedAt": int(time.time()),
                "clientSecretExpiresAt": int(time.time()) + 90 * 86400,
            })
        if path == "/device_authorization":
            log({"n": n, "op": "StartDeviceAuthorization"})
            return self.reply({
                "deviceCode": "fake-device-code", "userCode": "ABCD-EFGH",
                "verificationUri": "https://device.sso.example/",
                "verificationUriComplete": "https://device.sso.example/?user_code=ABCD-EFGH",
                "expiresIn": 600, "interval": 1,
            })
        if path == "/token":
            grant = b.get("grantType", "")
            log({"n": n, "op": "CreateToken", "grant": grant, "refreshToken": b.get("refreshToken", "")})
            resp = {"accessToken": f"fake-access-{n}", "expiresIn": TTL, "tokenType": "Bearer"}
            if grant.endswith("device_code") or ROTATE:
                resp["refreshToken"] = f"fake-refresh-{n}"
            return self.reply(resp)
        log({"n": n, "op": "unknown-POST", "path": self.path})
        self.reply({"message": "unknown"}, 404)

    def do_GET(self):
        global n
        n += 1
        path, _, qs = self.path.partition("?")
        if path == "/federation/credentials":
            q = urllib.parse.parse_qs(qs)
            bearer = self.headers.get("x-amz-sso_bearer_token", "")
            log({"n": n, "op": "GetRoleCredentials", "bearer": bearer,
                 "account": q.get("account_id", [""])[0], "role": q.get("role_name", [""])[0]})
            return self.reply({"roleCredentials": {
                "accessKeyId": f"ASIAFAKE{n:012d}", "secretAccessKey": f"fake-secret-{n}",
                "sessionToken": f"fake-session-{n}",
                "expiration": int((time.time() + 3600) * 1000),
            }})
        log({"n": n, "op": "unknown-GET", "path": self.path})
        self.reply({"message": "unknown"}, 404)

    def log_message(self, *a):
        pass


if __name__ == "__main__":
    print(f"fake SSO on 127.0.0.1:{PORT} rotate={ROTATE} ttl={TTL}", file=sys.stderr)
    ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()

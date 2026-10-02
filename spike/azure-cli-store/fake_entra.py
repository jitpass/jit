#!/usr/bin/env python3
# Copyright 2026 Meni Tasa
# SPDX-License-Identifier: LicenseRef-PolyForm-Perimeter-1.0.0
"""A stand-in for Entra ID (the v2.0 endpoints MSAL uses) and the two ARM
calls `az login` makes, over HTTPS with a self-signed cert (MSAL refuses a
non-https authority). Device-code and refresh grants rotate the refresh
token on every call, as Entra ID does; client_credentials serves a service
principal. Each request is logged to LOG as one JSON line."""
import base64, json, os, ssl, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get("PORT", "8443"))
LOG = os.environ.get("LOG", "req.jsonl")
BASE = f"https://127.0.0.1:{PORT}"
TENANT = "11111111-2222-3333-4444-555555555555"
SUB = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID = "99999999-8888-7777-6666-555555555555"
n = 0

def b64(d): return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

def id_token(client_id, tenant):
    now = int(time.time())
    return "e30." + b64({"aud": client_id, "iss": f"{BASE}/{tenant}/v2.0", "iat": now, "nbf": now, "exp": now + 3600,
                         "oid": OID, "sub": "sub-1", "tid": tenant, "preferred_username": "dev@example.com", "name": "Dev"}) + ".sig"

class H(BaseHTTPRequestHandler):
    def log(self, **kw):
        with open(LOG, "a") as f: f.write(json.dumps({"n": n, "method": self.command, "path": self.path.split("?")[0], **kw}) + "\n")
    def reply(self, obj, code=200):
        b = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b))); self.end_headers(); self.wfile.write(b)
    def do_GET(self):
        global n; n += 1
        p = self.path.split("?")[0]; self.log()
        if p.endswith("/v2.0/.well-known/openid-configuration"):
            t = p.split("/")[1]
            return self.reply({"issuer": f"{BASE}/{t}/v2.0", "authorization_endpoint": f"{BASE}/{t}/oauth2/v2.0/authorize",
                               "token_endpoint": f"{BASE}/{t}/oauth2/v2.0/token", "device_authorization_endpoint": f"{BASE}/{t}/oauth2/v2.0/devicecode",
                               "jwks_uri": f"{BASE}/{t}/discovery/v2.0/keys", "response_types_supported": ["code"],
                               "subject_types_supported": ["pairwise"], "id_token_signing_alg_values_supported": ["RS256"]})
        if p.endswith("/metadata/endpoints"):
            return self.reply({"name": "FakeCloud", "resourceManager": f"{BASE}/arm/", "portal": f"{BASE}/portal/",
                               "authentication": {"loginEndpoint": BASE, "audiences": [f"{BASE}/arm/"], "tenant": "common"},
                               "graphAudience": f"{BASE}/graph/", "suffixes": {}})
        if p.startswith("/arm/tenants"):
            return self.reply({"value": [{"id": f"/tenants/{TENANT}", "tenantId": TENANT, "displayName": "Fake", "defaultDomain": "fake.example"}]})
        if p.startswith("/arm/subscriptions"):
            return self.reply({"value": [{"id": f"/subscriptions/{SUB}", "subscriptionId": SUB, "tenantId": TENANT, "displayName": "Fake Sub", "state": "Enabled",
                                          "subscriptionPolicies": {}, "authorizationSource": "RoleBased", "managedByTenants": []}]})
        self.reply({"error": "not_found", "path": p}, 404)
    def do_POST(self):
        global n; n += 1
        body = urllib.parse.parse_qs(self.rfile.read(int(self.headers.get("Content-Length", 0))).decode())
        f = {k: v[0] for k, v in body.items()}
        p = self.path.split("?")[0]; t = p.split("/")[1]
        self.log(grant=f.get("grant_type"), refresh_token=f.get("refresh_token"), scope=f.get("scope"), client_id=f.get("client_id"))
        if p.endswith("/oauth2/v2.0/devicecode"):
            return self.reply({"device_code": "dc", "user_code": "ABCD", "verification_uri": "https://microsoft.com/devicelogin",
                               "expires_in": 900, "interval": 1, "message": "To sign in, enter the code ABCD"})
        if p.endswith("/oauth2/v2.0/token"):
            g = f.get("grant_type", "")
            tenant = TENANT if t in ("organizations", "common") else t
            out = {"token_type": "Bearer", "expires_in": 3600, "ext_expires_in": 3600, "scope": f.get("scope", ""),
                   "access_token": f"at-{n}"}
            if g == "client_credentials":
                return self.reply(out)
            out.update({"refresh_token": f"rt-{n}", "id_token": id_token(f.get("client_id"), tenant),
                        "client_info": b64({"uid": OID, "utid": tenant})})
            return self.reply(out)
        self.reply({"error": "not_found"}, 404)
    def log_message(self, *a): pass

srv = ThreadingHTTPServer(("127.0.0.1", PORT), H)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); ctx.load_cert_chain("cert.pem", "key.pem")
srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
srv.serve_forever()

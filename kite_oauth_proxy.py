"""
TradeLog Live — Kite Connect OAuth Proxy
=========================================
Handles:
  1. OAuth login flow  (/auth/login → Kite → /auth/callback → sends token to TradeLog)
  2. CORS proxy        (/api/<path> → api.kite.trade with proper auth)

Deploy to Render.com (free), Railway, or Fly.io.
Set env vars: KITE_API_KEY, KITE_API_SECRET

The api_secret NEVER leaves this server. TradeLog only ever holds the access_token.
"""

from flask import Flask, redirect, request, jsonify, Response
from flask_cors import CORS
import requests
import hashlib
import os
import json

app = Flask(__name__)
CORS(app, origins="*", allow_headers=["X-Access-Token", "Content-Type", "Authorization"])

API_KEY    = os.environ.get("KITE_API_KEY", "")
API_SECRET = os.environ.get("KITE_API_SECRET", "")
KITE_API   = "https://api.kite.trade"

# ── Auth routes ──────────────────────────────────────────────────────────────

@app.route("/auth/login")
def login():
    if not API_KEY:
        return "KITE_API_KEY not configured on server", 500
    url = f"https://kite.zerodha.com/connect/login?v=3&api_key={API_KEY}"
    return redirect(url)


@app.route("/auth/callback")
def callback():
    request_token = request.args.get("request_token", "")
    status = request.args.get("status", "")

    # User cancelled login
    if status and status != "success":
        return _popup_msg("error", "Login cancelled", "")

    if not request_token:
        return _popup_msg("error", "No request_token received", ""), 400

    # Exchange request_token for access_token
    # checksum = SHA-256( api_key + request_token + api_secret )
    raw = (API_KEY + request_token + API_SECRET).encode("utf-8")
    checksum = hashlib.sha256(raw).hexdigest()

    try:
        resp = requests.post(
            f"{KITE_API}/session/token",
            data={
                "api_key": API_KEY,
                "request_token": request_token,
                "checksum": checksum,
            },
            headers={"X-Kite-Version": "3"},
            timeout=15,
        )
        data = resp.json()

        if data.get("status") == "success":
            d             = data["data"]
            access_token  = d["access_token"]
            user_name     = d.get("user_name", "")
            user_id       = d.get("user_id", "")
            login_time    = d.get("login_time", "")
            return _popup_msg("success", user_name, access_token, user_id, login_time)
        else:
            err = data.get("message", "Unknown error from Zerodha")
            return _popup_msg("error", err, ""), 400

    except requests.exceptions.Timeout:
        return _popup_msg("error", "Request to Zerodha timed out", ""), 504
    except Exception as e:
        return _popup_msg("error", str(e), ""), 500


def _popup_msg(status, message, access_token, user_id="", login_time=""):
    """Return an HTML page that sends a postMessage to the opener and closes."""
    if status == "success":
        icon  = "✓"
        color = "#c8ff45"
        body  = f"Welcome, {message}. This window will close shortly."
    else:
        icon  = "✗"
        color = "#ff4d6a"
        body  = message

    payload = json.dumps({
        "type":         "kite-auth-success" if status == "success" else "kite-auth-error",
        "access_token": access_token,
        "user_name":    message if status == "success" else "",
        "user_id":      user_id,
        "login_time":   login_time,
        "message":      message,
    })

    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>TradeLog — Zerodha Auth</title>
  <link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500&display=swap" rel="stylesheet">
  <style>
    *{{margin:0;padding:0;box-sizing:border-box;}}
    body{{background:#07090f;color:#e2e8f5;font-family:'DM Sans',sans-serif;
         display:flex;align-items:center;justify-content:center;height:100vh;}}
    .card{{text-align:center;padding:48px 44px;background:#0d1017;
           border-radius:18px;border:1px solid #1e2535;max-width:360px;}}
    .icon{{font-size:56px;margin-bottom:20px;}}
    h2{{font-size:20px;color:{color};margin-bottom:10px;font-weight:600;}}
    p{{font-size:13px;color:#8a97b5;line-height:1.6;}}
    .bar{{height:3px;background:{color};border-radius:2px;margin-top:28px;
          animation:shrink 1.8s linear forwards;}}
    @keyframes shrink{{from{{width:100%}}to{{width:0%}}}}
  </style>
</head>
<body>
<div class="card">
  <div class="icon">{icon}</div>
  <h2>{"Connected!" if status == "success" else "Auth Failed"}</h2>
  <p>{body}</p>
  <div class="bar"></div>
</div>
<script>
  try {{
    if (window.opener) {{
      window.opener.postMessage({payload}, "*");
    }}
  }} catch(e) {{ console.error(e); }}
  setTimeout(() => window.close(), 1800);
</script>
</body>
</html>"""


# ── CORS proxy ───────────────────────────────────────────────────────────────

@app.route("/api/<path:path>", methods=["GET", "OPTIONS"])
def proxy(path):
    if request.method == "OPTIONS":
        return Response("", 200, {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Headers": "X-Access-Token, Content-Type",
            "Access-Control-Allow-Methods": "GET, OPTIONS",
        })

    access_token = request.headers.get("X-Access-Token", "")
    if not access_token:
        return jsonify({"status": "error", "message": "Missing X-Access-Token header"}), 401

    try:
        r = requests.get(
            f"{KITE_API}/{path}",
            params=dict(request.args),
            headers={
                "Authorization": f"token {API_KEY}:{access_token}",
                "X-Kite-Version": "3",
            },
            timeout=12,
        )
        return Response(
            r.content,
            r.status_code,
            {
                "Content-Type": "application/json",
                "Access-Control-Allow-Origin": "*",
            },
        )
    except requests.exceptions.Timeout:
        return jsonify({"status": "error", "message": "Zerodha API timeout"}), 504
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ── Health ────────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "TradeLog Kite OAuth Proxy",
        "configured": bool(API_KEY and API_SECRET),
    })


# ── Entry point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    print(f"TradeLog Kite Proxy — listening on :{port}")
    print(f"API_KEY configured: {bool(API_KEY)}")
    app.run(host="0.0.0.0", port=port)

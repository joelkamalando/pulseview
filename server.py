#!/usr/bin/env python3
"""PulseView backend — Phases 1-3.

Small stdlib-only server that:
  * runs the Google OAuth 2.0 authorization-code flow with PKCE,
  * stores tokens in ~/.config/pulseview/tokens.json (mode 0600),
  * fetches Joel's Fitbit data from the Google Health API (v4),
  * serves it as one cached JSON feed at /api/stats,
  * serves the 600x600 glasses web app at /.

Hosted mode (Render, Phase 3): set env vars and the server adapts —
  PORT (Render assigns it), PULSEVIEW_HOST (0.0.0.0),
  PULSEVIEW_CLIENT_ID / PULSEVIEW_CLIENT_SECRET (Web OAuth client),
  PULSEVIEW_REDIRECT_URI (public https://.../oauth/callback),
  PULSEVIEW_TOKENS (JSON of the token file, since Render has no
  persistent disk), PULSEVIEW_KEY (optional access key required as
  ?k= on / and /api/stats).

Tokens are never printed to logs or replies.
"""

import base64
import hashlib
import html
import json
import os
import secrets
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from zoneinfo import ZoneInfo

# ---------------------------------------------------------------- config

CONFIG_DIR = os.path.expanduser("~/.config/pulseview")
CONFIG_PATH = os.path.join(CONFIG_DIR, "config.json")
TOKENS_PATH = os.path.join(CONFIG_DIR, "tokens.json")
PORT = int(os.environ.get("PORT", "8765"))
HOST = os.environ.get("PULSEVIEW_HOST", "127.0.0.1")
# Public redirect URI for the hosted (Web-client) flow; defaults to the
# local loopback used by the Desktop client.
REDIRECT_URI = os.environ.get(
    "PULSEVIEW_REDIRECT_URI", f"http://127.0.0.1:{PORT}/oauth/callback")
# Optional access key: when set, / and /api/stats require ?k=<key>.
ACCESS_KEY = os.environ.get("PULSEVIEW_KEY") or None
TORONTO = ZoneInfo("America/Toronto")

AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
TOKEN_URL = "https://oauth2.googleapis.com/token"
API_BASE = "https://health.googleapis.com/v4"

SCOPES = [
    "https://www.googleapis.com/auth/googlehealth.activity_and_fitness.readonly",
    "https://www.googleapis.com/auth/googlehealth.health_metrics_and_measurements.readonly",
]

# Pending PKCE flows: state -> code_verifier
_pending = {}
_pending_path = os.path.join(CONFIG_DIR, "pending.json")


def _load_pending():
    try:
        with open(_pending_path) as f:
            _pending.update(json.load(f))
    except FileNotFoundError:
        pass


def _save_pending():
    os.makedirs(CONFIG_DIR, exist_ok=True)
    tmp = _pending_path + ".tmp"
    with open(tmp, "w") as f:
        json.dump(_pending, f)
    os.chmod(tmp, 0o600)
    os.replace(tmp, _pending_path)
_cache = {"at": 0, "data": None}
_cache_lock = threading.Lock()


def load_config():
    # Env vars (Render secrets) win over the local config file.
    env_id = os.environ.get("PULSEVIEW_CLIENT_ID")
    env_secret = os.environ.get("PULSEVIEW_CLIENT_SECRET")
    if env_id:
        cfg = {"client_id": env_id}
        if env_secret:
            cfg["client_secret"] = env_secret
        return cfg
    try:
        with open(CONFIG_PATH) as f:
            return json.load(f)
    except FileNotFoundError:
        return {"client_id": "REPLACE_WITH_CLIENT_ID"}


# In-memory token cache: on hosts without a persistent disk (Render),
# tokens survive in memory for the life of the process and are seeded
# from the PULSEVIEW_TOKENS env var at startup.
_tokens_mem = None


def load_tokens():
    global _tokens_mem
    if _tokens_mem is not None:
        return _tokens_mem
    try:
        with open(TOKENS_PATH) as f:
            _tokens_mem = json.load(f)
            return _tokens_mem
    except FileNotFoundError:
        pass
    env_tokens = os.environ.get("PULSEVIEW_TOKENS")
    if env_tokens:
        try:
            _tokens_mem = json.loads(env_tokens)
            return _tokens_mem
        except json.JSONDecodeError:
            pass
    return None


def save_tokens(tokens):
    global _tokens_mem
    _tokens_mem = tokens
    try:
        os.makedirs(CONFIG_DIR, exist_ok=True)
        tmp = TOKENS_PATH + ".tmp"
        with open(tmp, "w") as f:
            json.dump(tokens, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, TOKENS_PATH)
    except OSError:
        pass  # no writable disk (e.g. hosted); memory copy is authoritative


# ---------------------------------------------------------------- oauth

def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def start_oauth():
    verifier = _b64url(secrets.token_bytes(32))
    challenge = _b64url(hashlib.sha256(verifier.encode("ascii")).digest())
    state = _b64url(secrets.token_bytes(16))
    _pending[state] = verifier
    _save_pending()
    cfg = load_config()
    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(SCOPES),
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "access_type": "offline",
        "prompt": "consent",
        "state": state,
    }
    return AUTH_URL + "?" + urllib.parse.urlencode(params)


def exchange_code(code, verifier):
    cfg = load_config()
    body = urllib.parse.urlencode({
        "client_id": cfg["client_id"],
        "client_secret": cfg.get("client_secret", ""),
        "code": code,
        "code_verifier": verifier,
        "grant_type": "authorization_code",
        "redirect_uri": REDIRECT_URI,
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    last_err = None
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=45) as resp:
                data = json.load(resp)
            break
        except urllib.error.HTTPError as e:
            # 4xx (e.g. bad code/secret) will not fix itself: fail fast
            detail = e.read().decode("utf-8", "replace")[:300]
            print(f"token exchange HTTP {e.code}: {detail}", flush=True)
            raise RuntimeError(f"token exchange failed: HTTP {e.code}: {detail}")
        except Exception as e:  # transient network stall: retry
            last_err = e
            print(f"token exchange attempt {attempt + 1} failed ({type(e).__name__}); retrying", flush=True)
            time.sleep(2)
    else:
        raise last_err
    tokens = {
        "access_token": data["access_token"],
        "refresh_token": data.get("refresh_token"),
        "expires_at": int(time.time()) + int(data.get("expires_in", 3600)) - 60,
        "scope": data.get("scope", ""),
    }
    if tokens["refresh_token"]:
        save_tokens(tokens)
    return tokens


def refresh_access_token(tokens):
    cfg = load_config()
    body = urllib.parse.urlencode({
        "client_id": cfg["client_id"],
        "client_secret": cfg.get("client_secret", ""),
        "refresh_token": tokens["refresh_token"],
        "grant_type": "refresh_token",
    }).encode()
    req = urllib.request.Request(TOKEN_URL, data=body,
                                 headers={"Content-Type": "application/x-www-form-urlencoded"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.load(resp)
    tokens["access_token"] = data["access_token"]
    tokens["expires_at"] = int(time.time()) + int(data.get("expires_in", 3600)) - 60
    if data.get("refresh_token"):
        tokens["refresh_token"] = data["refresh_token"]
    save_tokens(tokens)
    return tokens


def get_access_token():
    tokens = load_tokens()
    if not tokens:
        return None
    if tokens.get("expires_at", 0) <= int(time.time()):
        tokens = refresh_access_token(tokens)
    return tokens["access_token"]


# ---------------------------------------------------------------- health api

def _api(method, path, body=None, params=None):
    token = get_access_token()
    if not token:
        raise RuntimeError("not authorized")
    url = API_BASE + path
    if params:
        url += "?" + urllib.parse.urlencode(params)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": "Bearer " + token,
        "Content-Type": "application/json",
    })
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except (TimeoutError, urllib.error.URLError) as e:
        # transient egress stall: one retry with a fresh token state
        time.sleep(2)
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as e2:
            detail = e2.read().decode("utf-8", "replace")[:500]
            raise RuntimeError(f"Google Health API {method} {path} -> HTTP {e2.code}: {detail}")
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:500]
        raise RuntimeError(f"Google Health API {method} {path} -> HTTP {e.code}: {detail}")


def _rfc3339(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _today_bounds():
    """Midnight-to-midnight today in Toronto, as UTC datetimes."""
    now = datetime.now(TORONTO)
    start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    end = start + timedelta(days=1)
    return start, end


def _week_bounds():
    """Monday 00:00 to next Monday 00:00 (Toronto) for the current week."""
    now = datetime.now(TORONTO)
    start = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=7)


def _civil_range(start, end):
    def civil(dt):
        return {"date": {"year": dt.year, "month": dt.month, "day": dt.day},
                "time": {"hours": dt.hour, "minutes": dt.minute, "seconds": dt.second}}
    return {"start": civil(start), "end": civil(end)}


def fetch_stats():
    now = datetime.now(TORONTO)
    today_start, today_end = _today_bounds()
    week_start, week_end = _week_bounds()

    # --- latest heart rate (last 6 hours, list) ---
    # NOTE: do NOT pass a `filter` query param — it makes the connection get
    # reset (proxy/API rejects it). List recent points and filter client-side.
    hr = {"bpm": None, "at": None, "age_seconds": None}
    try:
        resp = _api("GET", "/users/me/dataTypes/heart-rate/dataPoints", params={
            "pageSize": 500,
        })
        points = resp.get("dataPoints", [])
        if points:
            latest = max(points, key=lambda p: p["heartRate"]["sampleTime"]["physicalTime"])
            at = datetime.fromisoformat(
                latest["heartRate"]["sampleTime"]["physicalTime"].replace("Z", "+00:00"))
            hr = {"bpm": int(latest["heartRate"]["beatsPerMinute"]),
                  "at": at.astimezone(TORONTO).isoformat(),
                  "age_seconds": max(0, int((datetime.now(timezone.utc) - at).total_seconds()))}
    except Exception as e:
        hr = {"bpm": None, "at": None, "age_seconds": None, "error": str(e)[:200]}

    # --- steps today (daily rollup) ---
    # rollup payloads use aggregated names (countSum), not the raw field (count)
    steps_today = None
    try:
        resp = _api("POST", "/users/me/dataTypes/steps/dataPoints:dailyRollUp", body={
            "range": _civil_range(today_start, today_end),
            "windowSizeDays": 1,
        })
        pts = resp.get("rollupDataPoints", [])
        if pts:
            steps_today = int(pts[0]["steps"]["countSum"])
    except Exception as e:
        steps_today = None

    # --- total calories today (daily rollup) ---
    calories_today = None
    try:
        resp = _api("POST", "/users/me/dataTypes/total-calories/dataPoints:dailyRollUp", body={
            "range": _civil_range(today_start, today_end),
            "windowSizeDays": 1,
        })
        pts = resp.get("rollupDataPoints", [])
        if pts:
            # total-calories rollup payload shape varies; read common fields
            dp = pts[0]
            calories_today = _extract_calories(dp)
    except Exception:
        calories_today = None

    # --- exercise sessions: today + this week (no filter param; client-side) ---
    workouts_today, workouts_week = [], []
    try:
        page_token = None
        seen = 0
        for _ in range(5):  # page through until we pass the week start
            params = {"pageSize": 100}
            if page_token:
                params["pageToken"] = page_token
            resp = _api("GET", "/users/me/dataTypes/exercise/dataPoints", params=params)
            batch = resp.get("dataPoints", [])
            if not batch:
                break
            oldest = None
            for p in batch:
                ex = p.get("exercise", {})
                iv = ex.get("interval", {})
                st = iv.get("startTime")
                if not st:
                    continue
                start = datetime.fromisoformat(st.replace("Z", "+00:00")).astimezone(TORONTO)
                if oldest is None or start < oldest:
                    oldest = start
                if start < week_start:
                    continue
                ms = ex.get("metricsSummary", {})
                item = {
                    "type": ex.get("exerciseType"),
                    "name": ex.get("displayName"),
                    "start": start.isoformat(),
                    "duration_seconds": _parse_duration(ex.get("activeDuration")),
                    "calories_kcal": ms.get("caloriesKcal"),
                    "steps": int(ms["steps"]) if ms.get("steps") else None,
                    "avg_hr": int(ms["averageHeartRateBeatsPerMinute"]) if ms.get("averageHeartRateBeatsPerMinute") else None,
                }
                if start.date() == now.date():
                    workouts_today.append(item)
                workouts_week.append(item)
            seen += len(batch)
            page_token = resp.get("nextPageToken")
            if not page_token or (oldest is not None and oldest < week_start):
                break
    except Exception as e:
        workouts_today = workouts_today or []
        workouts_week = workouts_week or []

    return {
        "fetched_at": datetime.now(TORONTO).isoformat(),
        "timezone": "America/Toronto",
        "heart_rate": hr,
        "steps_today": steps_today,
        "calories_today": calories_today,
        "workouts_today": workouts_today,
        "workouts_this_week": len(workouts_week),
        "workouts_this_week_detail": workouts_week,
        "plan_target_per_week": 5,
    }


def _extract_calories(dp):
    # total-calories rollup points carry the value under one of these keys;
    # rollups use aggregated names (kcalSum), raw points use kcal
    for key in ("totalCalories", "calories", "totalEnergyBurned"):
        v = dp.get(key)
        if isinstance(v, dict):
            for sub in ("kcalSum", "kcal", "value"):
                if sub in v:
                    return float(v[sub])
        elif isinstance(v, (int, float)):
            return float(v)
    return None


def _parse_duration(s):
    if not s:
        return None
    # google-duration like "1800s" or "30m"
    try:
        if s.endswith("s"):
            return int(float(s[:-1]))
    except ValueError:
        pass
    return None


def get_stats_cached():
    with _cache_lock:
        if _cache["data"] and time.time() - _cache["at"] < 60:
            return _cache["data"]
        data = fetch_stats()
        _cache["data"] = data
        _cache["at"] = time.time()
        return data


# ---------------------------------------------------------------- http

PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>PulseView — test</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:40px auto;padding:0 16px}
h1{font-size:28px}.stat{font-size:20px;margin:12px 0}.big{font-size:56px;font-weight:700}
small{color:#666}pre{background:#f4f4f4;padding:12px;overflow:auto}</style></head>
<body><h1>PulseView — backend test page</h1>
<div id="status">Loading…</div>
<div id="stats"></div>
<script>
async function load(){
  const r = await fetch('/api/stats'); const d = await r.json();
  const el = document.getElementById('stats');
  const hr = d.heart_rate;
  el.innerHTML =
    '<div class="stat">Heart rate<br><span class="big">' + (hr.bpm ?? '—') + '</span> bpm' +
    (hr.at ? ' <small>· ' + hr.age_seconds + 's ago</small>' : '') + '</div>' +
    '<div class="stat">Steps today<br><span class="big">' + (d.steps_today ?? '—') + '</span></div>' +
    '<div class="stat">Calories today<br><span class="big">' + (d.calories_today ?? '—') + '</span> kcal</div>' +
    '<div class="stat">Workouts today: <b>' + d.workouts_today.length + '</b> · this week: <b>' +
    d.workouts_this_week + ' / ' + d.plan_target_per_week + '</b></div>' +
    '<small>Fetched ' + d.fetched_at + '</small><pre>' + JSON.stringify(d, null, 2) + '</pre>';
  document.getElementById('status').textContent = '';
}
load(); setInterval(load, 60000);
</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        # keep logs free of tokens and query strings
        print(f"[{datetime.now().isoformat()}] {self.command} {self.path.split('?')[0]}")

    def _send_json(self, obj, status=200):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_html(self, text, status=200):
        body = text.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        # Optional access key (hosted mode): / and /api/stats need ?k=<key>.
        # /oauth/* is exempt — Google redirects back without the key.
        if ACCESS_KEY and path in ("/", "/api/stats", "/debug"):
            qs = urllib.parse.parse_qs(parsed.query)
            if qs.get("k", [None])[0] != ACCESS_KEY:
                self._send_json({"error": "forbidden"}, 403)
                return
        if path == "/":
            tokens = load_tokens()
            if not tokens:
                self._send_html(
                    "<h1>PulseView backend</h1><p>Not connected yet.</p>"
                    '<p><a href="/oauth/start">Connect your Google account</a></p>')
            else:
                # the glasses web app (600x600); read from disk so edits apply live
                try:
                    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "app.html"), "rb") as f:
                        body = f.read()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                except FileNotFoundError:
                    self._send_html(PAGE)
        elif path == "/debug":
            self._send_html(PAGE)
        elif path == "/oauth/start":
            self.send_response(302)
            self.send_header("Location", start_oauth())
            self.end_headers()
        elif path == "/oauth/callback":
            qs = urllib.parse.parse_qs(parsed.query)
            code = qs.get("code", [None])[0]
            state = qs.get("state", [None])[0]
            err = qs.get("error", [None])[0]
            if err:
                self._send_html(f"<h1>Authorization failed</h1><p>{html.escape(err)}</p>", 400)
                return
            verifier = _pending.pop(state, None)
            _save_pending()
            if not code or not verifier:
                self._send_html("<h1>Authorization failed</h1><p>Missing code or expired session. Try again.</p>", 400)
                return
            try:
                exchange_code(code, verifier)
            except Exception as e:
                self._send_html(f"<h1>Token exchange failed</h1><p>{html.escape(str(e)[:300])}</p>", 500)
                return
            self._send_html("<h1>Connected ✓</h1><p>PulseView can now read your health data. "
                            'You can close this tab. <a href="/">See your stats</a></p>')
        elif path == "/api/stats":
            try:
                self._send_json(get_stats_cached())
            except Exception as e:
                self._send_json({"error": str(e)[:300]}, 500)
        elif path == "/api/status":
            tokens = load_tokens()
            self._send_json({
                "authorized": bool(tokens),
                "token_expires_at": tokens.get("expires_at") if tokens else None,
                "has_refresh_token": bool(tokens and tokens.get("refresh_token")),
                "cache_age_seconds": int(time.time() - _cache["at"]) if _cache["data"] else None,
            })
        else:
            self._send_json({"error": "not found"}, 404)


if __name__ == "__main__":
    os.makedirs(CONFIG_DIR, exist_ok=True)
    _load_pending()
    if not os.path.exists(CONFIG_PATH):
        with open(CONFIG_PATH, "w") as f:
            json.dump({"client_id": "REPLACE_WITH_DESKTOP_CLIENT_ID"}, f, indent=2)
        print(f"Wrote placeholder config to {CONFIG_PATH} — fill in client_id.")
    print(f"PulseView backend on http://{HOST}:{PORT}", flush=True)
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()

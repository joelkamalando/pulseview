# PulseView

Fitbit stats (heart rate, steps, calories, workouts) on Meta Ray-Ban Display
glasses, via the Google Health API. One small Python server (stdlib only):

- `server.py` — OAuth (PKCE), Google Health API client, `/api/stats` JSON feed,
  and the 600×600 glasses web app at `/`.
- `app.html` — the glasses UI (two screens: Right now / Today).
- `render.yaml` — Render free-tier deployment.

## Local run

```sh
python3 server.py   # http://127.0.0.1:8765
```

## Hosted run (Render)

Set these env vars in the Render dashboard:

| Var | Value |
|---|---|
| `PULSEVIEW_HOST` | `0.0.0.0` |
| `PULSEVIEW_CLIENT_ID` | Google OAuth **Web** client id |
| `PULSEVIEW_CLIENT_SECRET` | Google OAuth **Web** client secret |
| `PULSEVIEW_REDIRECT_URI` | `https://<service>.onrender.com/oauth/callback` |
| `PULSEVIEW_TOKENS` | JSON of `tokens.json` (the refresh token) |
| `PULSEVIEW_KEY` | access key, required as `?k=` on `/` and `/api/stats` |

Then visit `https://<service>.onrender.com/oauth/start` once to authorize
(the Web client's redirect URI must list the Render callback URL first).

## Notes

- Render's free tier has no persistent disk: tokens are seeded from
  `PULSEVIEW_TOKENS` and kept in memory; the file is a best-effort cache.
- Free services sleep after 15 min idle and take ~30–60s to wake; the
  glasses page retries every 60s, so a cold start just looks like one
  slow refresh.

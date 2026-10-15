# Website Change Detector

A Flask web application that monitors public HTTP/HTTPS pages, saves unique text snapshots, filters common noise, displays version history, and compares changes.

## Features in this MVP
- Add public page URLs, names, check intervals (15 minutes to 24 hours), sensitivity labels, and CSS selectors to ignore.
- Scheduled checks and a manual **Check now** action.
- Text normalization, timestamp/date filtering, and script/style removal to reduce noisy changes.
- SQLite snapshot history and SHA-256 content hashes; duplicate snapshots are not stored.
- Side-by-side-style text comparison and unified text diffs.
- Optional webhook alert via `ALERT_WEBHOOK_URL`.
- Public URL checks that block local/private/reserved IP addresses.
- Dashboard states: OK, ERROR, BLOCKED.

## Important scope note
This is a practical starter MVP, not yet the full advanced specification. It currently uses HTTP requests and HTML parsing rather than a headless browser; screenshots, a visual region picker, email/Telegram-specific integrations, keyword alerts, and an RSS feed are not implemented. Sensitivity is stored as a setting but does not yet alter the comparison threshold. Add these as follow-up features if the rubric requires them.

## Run locally
Python 3.10+ recommended.

```bash
python -m venv .venv
# macOS/Linux
source .venv/bin/activate
# Windows: .venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000.

## Deploy on Render
1. Create a GitHub repository and upload these files.
2. In Render, choose **New + → Blueprint** and connect the repository.
3. Render detects `render.yaml`; create the web service.
4. Wait for deployment, then open the `onrender.com` URL.
5. Note: the included SQLite database is ephemeral on many free hosting plans, and the in-process scheduler runs only while this web service is awake. For persistent production use, configure PostgreSQL and a separate worker/scheduler.

## Optional webhook
Set the environment variable `ALERT_WEBHOOK_URL` to a webhook URL you control. It sends a short notification when a new snapshot differs from the previous snapshot. Do not commit secrets to GitHub.

## Safe use
Monitor public pages only, respect site terms and robots policies, keep check intervals reasonable, and do not attempt to bypass logins, CAPTCHAs, or access controls.

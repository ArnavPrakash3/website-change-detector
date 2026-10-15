import os
import re
import json
import time
import hashlib
import ipaddress
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse
from difflib import HtmlDiff, unified_diff

import requests
from bs4 import BeautifulSoup
from flask import Flask, render_template, request, redirect, url_for, flash, abort
from flask_sqlalchemy import SQLAlchemy
from apscheduler.schedulers.background import BackgroundScheduler

app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "change-this-before-deploying")
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///monitor.db").replace("postgres://", "postgresql://", 1)
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

MIN_INTERVAL = 15
MAX_INTERVAL = 24 * 60
MAX_TEXT_CHARS = 200_000

class Monitor(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    interval_minutes = db.Column(db.Integer, nullable=False, default=60)
    sensitivity = db.Column(db.String(20), nullable=False, default="medium")
    ignore_selectors = db.Column(db.Text, nullable=False, default="")
    status = db.Column(db.String(20), nullable=False, default="OK")
    last_checked = db.Column(db.DateTime, nullable=True)
    last_changed = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.String(500), nullable=True)
    last_hash = db.Column(db.String(64), nullable=True)

class Snapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    monitor_id = db.Column(db.Integer, db.ForeignKey("monitor.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    content_hash = db.Column(db.String(64), nullable=False)
    text_content = db.Column(db.Text, nullable=False)
    screenshot_path = db.Column(db.String(500), nullable=True)

    monitor = db.relationship("Monitor", backref=db.backref("snapshots", lazy=True, cascade="all, delete-orphan"))

def safe_public_url(url):
    """Allow only public HTTP(S) hosts; block localhost and private/reserved IP ranges."""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname:
            return False
        if parsed.username or parsed.password:
            return False
        host = parsed.hostname.lower()
        if host in ("localhost",) or host.endswith(".localhost") or host.endswith(".local"):
            return False
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            addresses = [ipaddress.ip_address(item[4][0]) for item in socket.getaddrinfo(host, None)]
        return bool(addresses) and all(ip.is_global for ip in addresses)
    except Exception:
        return False

def normalize_page(html, ignored_selectors=""):
    soup = BeautifulSoup(html, "html.parser")
    for node in soup(["script", "style", "noscript", "svg", "iframe"]):
        node.decompose()
    selectors = [x.strip() for x in (ignored_selectors or "").splitlines() if x.strip()]
    for selector in selectors:
        try:
            for node in soup.select(selector):
                node.decompose()
        except Exception:
            continue
    text = soup.get_text(" ", strip=True)
    text = re.sub(r"\s+", " ", text)
    # Remove common time-like strings and standalone counters to reduce noisy changes.
    text = re.sub(r"\b\d{1,2}:\d{2}(?::\d{2})?\b", "[TIME]", text)
    text = re.sub(r"\b\d{4}-\d{2}-\d{2}\b", "[DATE]", text)
    return text[:MAX_TEXT_CHARS]

def send_webhook(monitor, old_text, new_text):
    webhook = os.environ.get("ALERT_WEBHOOK_URL", "").strip()
    if not webhook:
        return
    # Never send page content to a webhook unless the owner intentionally configures one.
    payload = {
        "text": f"Website Change Detector: '{monitor.name}' changed.\nURL: {monitor.url}\nChecked: {datetime.now(timezone.utc).isoformat()}"
    }
    try:
        requests.post(webhook, json=payload, timeout=8)
    except requests.RequestException:
        app.logger.exception("Webhook notification failed")

def check_monitor(monitor_id):
    with app.app_context():
        monitor = db.session.get(Monitor, monitor_id)
        if not monitor:
            return
        monitor.last_checked = datetime.now(timezone.utc)
        if not safe_public_url(monitor.url):
            monitor.status = "BLOCKED"
            monitor.last_error = "Only public HTTP/HTTPS URLs are allowed."
            db.session.commit()
            return
        try:
            response = requests.get(
                monitor.url,
                timeout=20,
                headers={"User-Agent": "WebsiteChangeDetector/1.0 (public page monitor)"},
                allow_redirects=True,
            )
            if not safe_public_url(response.url):
                raise ValueError("Redirect destination is not a public URL.")
            response.raise_for_status()
            content = normalize_page(response.text, monitor.ignore_selectors)
            digest = hashlib.sha256(content.encode("utf-8")).hexdigest()
            old_snapshot = Snapshot.query.filter_by(monitor_id=monitor.id).order_by(Snapshot.id.desc()).first()
            if old_snapshot is None or digest != old_snapshot.content_hash:
                snap = Snapshot(monitor_id=monitor.id, content_hash=digest, text_content=content)
                db.session.add(snap)
                if old_snapshot is not None:
                    monitor.last_changed = datetime.now(timezone.utc)
                    send_webhook(monitor, old_snapshot.text_content, content)
            monitor.last_hash = digest
            monitor.status = "OK"
            monitor.last_error = None
        except Exception as exc:
            monitor.status = "ERROR"
            monitor.last_error = str(exc)[:490]
            app.logger.exception("Monitor check failed for %s", monitor.url)
        db.session.commit()

def due_checks():
    with app.app_context():
        now = datetime.now(timezone.utc)
        monitors = Monitor.query.all()
        for monitor in monitors:
            if monitor.last_checked is None:
                check_monitor(monitor.id)
            else:
                elapsed = (now - monitor.last_checked.replace(tzinfo=timezone.utc) if monitor.last_checked.tzinfo is None else now - monitor.last_checked).total_seconds() / 60
                if elapsed >= monitor.interval_minutes:
                    check_monitor(monitor.id)

@app.route("/")
def index():
    monitors = Monitor.query.order_by(Monitor.id.desc()).all()
    return render_template("index.html", monitors=monitors)

@app.route("/add", methods=["POST"])
def add_monitor():
    name = request.form.get("name", "").strip()
    url = request.form.get("url", "").strip()
    interval = request.form.get("interval", "60")
    sensitivity = request.form.get("sensitivity", "medium")
    ignored = request.form.get("ignore_selectors", "").strip()
    if not name or len(name) > 120:
        flash("Enter a name (maximum 120 characters).", "error")
        return redirect(url_for("index"))
    if not safe_public_url(url):
        flash("Enter a valid public HTTP or HTTPS URL. Local/private addresses are blocked.", "error")
        return redirect(url_for("index"))
    try:
        interval = int(interval)
    except ValueError:
        interval = 60
    if not MIN_INTERVAL <= interval <= MAX_INTERVAL:
        flash("Check interval must be between 15 minutes and 24 hours.", "error")
        return redirect(url_for("index"))
    if sensitivity not in ("low", "medium", "high"):
        sensitivity = "medium"
    monitor = Monitor(name=name, url=url, interval_minutes=interval, sensitivity=sensitivity, ignore_selectors=ignored)
    db.session.add(monitor)
    db.session.commit()
    check_monitor(monitor.id)
    flash("Monitor added. The first snapshot has been captured.", "success")
    return redirect(url_for("index"))

@app.route("/check/<int:monitor_id>", methods=["POST"])
def check_now(monitor_id):
    if not db.session.get(Monitor, monitor_id):
        abort(404)
    check_monitor(monitor_id)
    flash("Check finished. Review the monitor status and version history.", "success")
    return redirect(url_for("detail", monitor_id=monitor_id))

@app.route("/delete/<int:monitor_id>", methods=["POST"])
def delete_monitor(monitor_id):
    monitor = db.session.get(Monitor, monitor_id)
    if monitor:
        db.session.delete(monitor)
        db.session.commit()
        flash("Monitor deleted.", "success")
    return redirect(url_for("index"))

@app.route("/monitor/<int:monitor_id>")
def detail(monitor_id):
    monitor = db.session.get(Monitor, monitor_id)
    if not monitor:
        abort(404)
    snapshots = Snapshot.query.filter_by(monitor_id=monitor_id).order_by(Snapshot.id.desc()).all()
    diff_html = None
    if len(snapshots) >= 2:
        older, newer = snapshots[1], snapshots[0]
        diff_html = HtmlDiff(wrapcolumn=90).make_table(
            older.text_content.splitlines(), newer.text_content.splitlines(),
            fromdesc=f"Version {older.id}", todesc=f"Version {newer.id}", context=True, numlines=2
        )
    return render_template("detail.html", monitor=monitor, snapshots=snapshots, diff_html=diff_html)

@app.route("/compare/<int:monitor_id>/<int:old_id>/<int:new_id>")
def compare(monitor_id, old_id, new_id):
    monitor = db.session.get(Monitor, monitor_id)
    old = db.session.get(Snapshot, old_id)
    new = db.session.get(Snapshot, new_id)
    if not monitor or not old or not new or old.monitor_id != monitor_id or new.monitor_id != monitor_id:
        abort(404)
    diff = "\n".join(unified_diff(
        old.text_content.split(), new.text_content.split(),
        fromfile=f"Version {old.id}", tofile=f"Version {new.id}", lineterm=""
    ))
    return render_template("compare.html", monitor=monitor, old=old, new=new, diff=diff)

with app.app_context():
    db.create_all()

scheduler = BackgroundScheduler(daemon=True)
scheduler.add_job(due_checks, "interval", minutes=1, id="monitor-scheduler", max_instances=1, coalesce=True)
scheduler.start()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)

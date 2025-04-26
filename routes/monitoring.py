from flask import Blueprint, session, redirect, url_for, flash
import json, os
from services.domain_checker import check_liveness, check_ssl_expiration
from datetime import datetime




monitoring_bp = Blueprint('monitoring', __name__)

@monitoring_bp.route("/check_domains")
def check_domains():
    if "username" not in session:
        flash("Please log in first.")
        return redirect(url_for("auth.login"))

    username = session["username"]
    domains_file = os.path.join("data", f"{username}_domains.json")
    os.makedirs(os.path.dirname(domains_file), exist_ok=True)

    if not os.path.exists(domains_file):
        flash("No domains to check.")
        return redirect(url_for("dashboard.dashboard"))

    # First: Read domains
    try:
        with open(domains_file, "r") as f:
            domains = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        domains = []

    # Update each domain
    for d in domains:
        d["status"] = check_liveness(d["domain"])
        d["ssl_expiration"] = check_ssl_expiration(d["domain"])
        d["last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Now save safely (overwrite clean)
    with open(domains_file, "w") as f:
        json.dump(domains, f, indent=4)

    flash("Domains checked and updated.")
    return redirect(url_for("dashboard.dashboard"))


@monitoring_bp.route('/bulk_upload', methods=['GET', 'POST'])
def bulk_upload():
    return "Bulk Upload Page"  # You can return a real form later

@monitoring_bp.route('/update_domains')
def update_domains_route():
    if "username" not in session:
        flash("Please log in first.")
        return redirect(url_for("auth.login"))

    username = session["username"]
    domains_file = os.path.join("data", f"{username}_domains.json")
    os.makedirs(os.path.dirname(domains_file), exist_ok=True)

    if not os.path.exists(domains_file):
        flash("No domain list found.")
        return redirect(url_for("dashboard.dashboard"))

    with open(domains_file, "r+") as f:
        domains = json.load(f)
        for d in domains:
            d["status"] = check_liveness(d["domain"])
            d["ssl_expiration"] = check_ssl_expiration(d["domain"])
            d["last_checked"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        f.seek(0)
        json.dump(domains, f, indent=4)

    flash("All domains updated successfully.")
    return redirect(url_for("dashboard.dashboard"))



from flask import Blueprint, session, redirect, url_for, flash
import json, os

from services.domain_checker import check_liveness, check_ssl_expiration

monitoring_bp = Blueprint('monitoring', __name__)

def get_user_domains_file(username):
    return os.path.join("data", f"{username}_domains.json")

@monitoring_bp.route("/check_domains")
def check_domains():
    if "username" not in session:
        flash("Please log in first.")
        return redirect(url_for("auth.login"))

    username = session["username"]
    domains_file = get_user_domains_file(username)

    if not os.path.exists(domains_file):
        flash("No domain data found.")
        return redirect(url_for("dashboard.dashboard"))

    with open(domains_file, "r+") as f:
        domains = json.load(f)
        for d in domains:
            d["status"] = check_liveness(d["domain"])
            d["ssl_expiration"] = check_ssl_expiration(d["domain"])
        f.seek(0)
        json.dump(domains, f, indent=4)

    flash("Domains checked and updated.")
    return redirect(url_for("dashboard.dashboard"))

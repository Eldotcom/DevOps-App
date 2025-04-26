from flask import Blueprint, render_template, request, redirect, url_for, flash, session
import json
import os

dashboard_bp = Blueprint('dashboard', __name__)

def get_user_domains_file(username):
    return os.path.join("data", f"{username}_domains.json")

@dashboard_bp.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        flash("Please log in first.")
        return redirect(url_for("auth.login"))

    username = session["username"]
    domains_file = get_user_domains_file(username)

    # Ensure the data folder exists
    os.makedirs(os.path.dirname(domains_file), exist_ok=True)

    # Ensure user-specific domain file exists
    if not os.path.exists(domains_file):
        with open(domains_file, "w") as f:
            json.dump([], f)

    if request.method == "POST":
        domain = request.form.get("domain")
        if not domain:
            flash("Domain cannot be empty.")
            return redirect(url_for("dashboard.dashboard"))

        try:
            with open(domains_file, "r+") as f:
                domains = json.load(f)
                if domain in [d["domain"] for d in domains]:
                    flash("Domain already exists.")
                    return redirect(url_for("dashboard.dashboard"))

                domains.append({
                    "domain": domain,
                    "status": "Unknown",
                    "ssl_expiration": "Unknown"
                })

                f.seek(0)
                json.dump(domains, f, indent=4)
                f.truncate()  # Clean file after rewrite
        except json.JSONDecodeError:
            flash("Error reading your domain list. Resetting your data.")
            with open(domains_file, "w") as f:
                json.dump([], f)

        flash(f"Domain '{domain}' added successfully.")
        return redirect(url_for("dashboard.dashboard"))

    # GET method: show domains
    try:
        with open(domains_file, "r") as f:
            domains = json.load(f)
            if not isinstance(domains, list):
                raise ValueError("Invalid domain data.")
    except (json.JSONDecodeError, ValueError):
        flash("Error loading your domains. Resetting your data.")
        domains = []
        with open(domains_file, "w") as f:
            json.dump(domains, f)

    return render_template("dashboard.html", username=username, domains=domains)

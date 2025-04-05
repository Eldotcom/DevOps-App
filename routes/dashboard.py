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
    #domains_file = get_user_domains_file(username)
    domains_file = os.path.join("data", f"{username}_domains.json")

   # Make sure the data folder exists
    os.makedirs(os.path.dirname(domains_file), exist_ok=True)

    # Then ensure user-specific domain file exists
    if not os.path.exists(domains_file):
        with open(domains_file, "w") as f:
            json.dump([], f)


    if request.method == "POST":
        domain = request.form.get("domain")
        if not domain:
            flash("Domain cannot be empty.")
            return redirect(url_for("dashboard"))

        with open(domains_file, "r+") as f:
            domains = json.load(f)
            if domain in [d["domain"] for d in domains]:
                flash("Domain already exists.")
                return redirect(url_for("dashboard"))

            domains.append({
                "domain": domain,
                "status": "Unknown",
                "ssl_expiration": "Unknown"
            })

            f.seek(0)
            json.dump(domains, f, indent=4)

        flash(f"Domain '{domain}' added successfully.")
        return redirect(url_for("dashboard"))

    with open(domains_file, "r") as f:
        domains = json.load(f)

    return render_template("dashboard.html", username=username, domains=domains)

from flask import Flask, render_template, request, redirect, url_for, session, flash
import json
import os
import requests  # Import the requests library
import ssl
print(f"SSL module imported successfully: {ssl.OPENSSL_VERSION}")
import socket
from datetime import datetime

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a secure secret key

DATA_DIR = "data"
USERS_FILE = os.path.join(DATA_DIR, "users.json")

def get_user_domains_file(username):
    """Returns the file path for a user's domain data file."""
    return os.path.join(DATA_DIR, f"{username}_domains.json")


# Ensure the data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Initialize users.json if it doesn't exist
if not os.path.exists(USERS_FILE):
    with open(USERS_FILE, "w") as f:
        json.dump({}, f)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        if not username or not password:
            flash("Username and password are required!")
            return redirect(url_for("register"))

        with open(USERS_FILE, "r+") as f:
            users = json.load(f)
            if username in users:
                flash("Username already exists!")
                return redirect(url_for("register"))

            # Store credentials in plain text (to be encrypted later)
            users[username] = {"password": password}
            f.seek(0)
            json.dump(users, f, indent=4)
            flash("Registration successful! Please log in.")
            return redirect(url_for("login"))

    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        with open(USERS_FILE, "r") as f:
            users = json.load(f)

        if username in users and users[username]["password"] == password:
            session["username"] = username
            flash(f"Welcome, {username}!")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password!")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/logout")
def logout():
    session.pop("username", None)
    flash("You have been logged out.")
    return redirect(url_for("home"))

@app.route("/dashboard", methods=["GET", "POST"])
def dashboard():
    if "username" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    username = session["username"]
    domains_file = get_user_domains_file(username)

    # Ensure the user's domain file exists
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

            domains.append({"domain": domain, "status": "Unknown", "ssl_expiration": "Unknown"})
            f.seek(0)
            json.dump(domains, f, indent=4)

        flash(f"Domain '{domain}' added successfully.")
        return redirect(url_for("dashboard"))

    # Load domains to display on the dashboard
    with open(domains_file, "r") as f:
        domains = json.load(f)

    return render_template("dashboard.html", username=username, domains=domains)

@app.route("/check_domains", methods=["GET"])
def check_domains():
    app.logger.debug("Entered /check_domains route")
    if "username" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    username = session["username"]
    domains_file = get_user_domains_file(username)

    with open(domains_file, "r+") as f:
        domains = json.load(f)
        for domain_data in domains:
            domain = domain_data["domain"]

            # Check domain liveness
            try:
                response = requests.get(f"http://{domain}", timeout=5)
                domain_data["status"] = "Up" if response.status_code == 200 else "Down"
            except requests.exceptions.RequestException:
                domain_data["status"] = "Down"

            # Check SSL expiration
            try:
                context = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as sock:
                    with context.wrap_socket(sock, server_hostname=domain) as ssock:
                        cert = ssock.getpeercert()
                        expiration_date = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                        domain_data["ssl_expiration"] = expiration_date.strftime("%Y-%m-%d")
            except (ssl.SSLError, socket.error, ValueError):
                domain_data["ssl_expiration"] = "Error"

        # Save updated data back to the file
        f.seek(0)
        json.dump(domains, f, indent=4)
        f.truncate()

    flash("Domains checked successfully.")
    return redirect(url_for("dashboard"))

@app.route("/upload_domains", methods=["POST"])
def upload_domains():
    if "username" not in session:
        flash("Please log in first.")
        return redirect(url_for("login"))

    username = session["username"]
    domains_file = get_user_domains_file(username)

    # Check if a file was uploaded
    if "file" not in request.files:
        flash("No file uploaded.")
        return redirect(url_for("dashboard"))

    file = request.files["file"]

    # Validate the file
    if not file.filename.endswith(".txt"):
        flash("Invalid file format. Please upload a .txt file.")
        return redirect(url_for("dashboard"))

    # Read and process the file
    try:
        new_domains = file.read().decode("utf-8").splitlines()
        new_domains = [domain.strip() for domain in new_domains if domain.strip()]  # Remove empty lines
    except Exception as e:
        flash(f"Error reading file: {e}")
        return redirect(url_for("dashboard"))

    # Load existing domains
    with open(domains_file, "r+") as f:
        existing_domains = json.load(f)
        existing_domain_names = [d["domain"] for d in existing_domains]

        # Add new domains, avoiding duplicates
        for domain in new_domains:
            if domain not in existing_domain_names:
                existing_domains.append({"domain": domain, "status": "Unknown", "ssl_expiration": "Unknown"})

        # Save updated list back to the file
        f.seek(0)
        json.dump(existing_domains, f, indent=4)
        f.truncate()

        flash(f"{len(new_domains)} domains uploaded successfully.")
        return redirect(url_for("dashboard"))

if __name__ == "__main__":
    app.run(debug=True)

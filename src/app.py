from flask import Flask, request, render_template, redirect, url_for, jsonify, session, flash
import json
import os
import requests  # Import the requests library
import ssl
#print(f"SSL module imported successfully: {ssl.OPENSSL_VERSION}")
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

app = Flask(__name__)
app.secret_key = "your_secret_key"  # Replace with a secure secret key

USER_FILE = os.path.join("app", "users.json")
DOMAIN_FILE_TEMPLATE = os.path.join("app", "{}_domains.json")

def load_json(filepath):
    """Load JSON data from a file, creating the directory/file if necessary."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)  # Ensure the directory exists
    if not os.path.exists(filepath):  # Create the file if it doesn't exist
        with open(filepath, 'w') as f:
            json.dump([], f)  # Initialize with an empty list
    with open(filepath, 'r') as f:
        return json.load(f)


def save_json(filepath, data):
    """Saves data to a JSON file."""
    with open(filepath, 'w') as f:
        json.dump(data, f, indent=4)


def check_liveness(domain):
    """Check if the domain is live."""
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        return "Up" if response.status_code == 200 else "Down"
    except:
        return "Down"

def check_ssl(domain):
    """Check the SSL certificate of a domain."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                exp_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                return exp_date.strftime('%Y-%m-%d')
    except:
        return "N/A"
    

def update_domains(username):
    """Update the status and SSL expiration of all domains for a user."""
    domain_file = DOMAIN_FILE_TEMPLATE.format(username)
    domains = load_json(domain_file)

    for domain_entry in domains:
        domain = domain_entry["domain"]
        domain_entry["status"] = check_liveness(domain)
        domain_entry["ssl_expiration"] = check_ssl(domain)

    save_json(domain_file, domains)

    from concurrent.futures import ThreadPoolExecutor

def background_update(username):
    """Run the domain updates in a background thread."""
    with ThreadPoolExecutor() as executor:
        executor.submit(update_domains, username)


#-----------------------------------------------------------------------------------------
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
#-----------------------------------------------------------------------------------------
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
#-----------------------------------------------------------------------------------------
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
#-----------------------------------------------------------------------------------------
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
#-----------------------------------------------------------------------------------------
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
#-----------------------------------------------------------------------------------------
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
#-----------------------------------------------------------------------------------------

@app.route('/bulk_upload', methods=['GET', 'POST'])
def bulk_upload():
    """Endpoint for bulk domain upload."""
    if 'username' not in session:
        return redirect(url_for('main.login'))

    username = session['username']  # Ensure the username is correctly set
    domain_file = DOMAIN_FILE_TEMPLATE.format(username)  # Build the correct file path

    # Create the "app" directory if it doesn't exist
    os.makedirs(os.path.dirname(domain_file), exist_ok=True)

    if request.method == 'POST':
        uploaded_file = request.files.get('domain_file')
        if not uploaded_file or uploaded_file.filename == '':
            return jsonify({"status": "Error", "message": "No file uploaded."})

        # Validate file extension
        if not uploaded_file.filename.endswith('.txt'):
            return jsonify({"status": "Error", "message": "Invalid file format. Only .txt allowed."})

        # Process file
        file_content = uploaded_file.read().decode('utf-8').strip().splitlines()
        domains_data = load_json(domain_file)

        for line in file_content:
            domain = line.strip()
            if domain and '.' in domain:
                if not any(d['domain'] == domain for d in domains_data):
                    domains_data.append({
                        "domain": domain,
                        "status": "Pending",
                        "ssl_expiration": "N/A",
                        "ssl_issuer": "N/A"
                    })

        save_json(domain_file, domains_data)
        return jsonify({"status": "Success", "message": "Bulk upload successful!"})

    return render_template('bulk_upload.html')

#-----------------------------------------------------------------------------------------
@app.route('/update_domains')
def update_domains_route():
    if 'username' not in session:
        return redirect(url_for('main.login'))

    username = session['username']
    update_domains(username)
    flash("Domains updated successfully!", "success")
    return redirect(url_for('dashboard'))
#-----------------------------------------------------------------------------------------
@app.route('/clear_domains', methods=['POST'])
def clear_domains():
    global checked_domains
    checked_domains = []  # Reset the list
    return jsonify({"message": "Checked domains cleared successfully"}), 200
#-----------------------------------------------------------------------------------------

if __name__ == "__main__":
    app.run(debug=True)

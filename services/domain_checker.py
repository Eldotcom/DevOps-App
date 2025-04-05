import requests
import ssl
import socket
from datetime import datetime

def check_liveness(domain):
    try:
        res = requests.get(f"http://{domain}", timeout=3)
        return "Up" if res.status_code == 200 else "Down"
    except Exception:
        return "Down"

def check_ssl_expiration(domain):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                expiry_date = datetime.strptime(cert['notAfter'], "%b %d %H:%M:%S %Y %Z")
                return expiry_date.strftime("%Y-%m-%d")
    except Exception:
        return "Unknown"

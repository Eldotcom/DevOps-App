import requests

BASE_URL = "http://127.0.0.1:5000"

def test_register_and_login():
    # הרשמה
    register_response = requests.post(f"{BASE_URL}/register", json={
        "username": "testuser",
        "password": "testpass"
    })
    assert register_response.status_code == 200

    # התחברות
    login_response = requests.post(f"{BASE_URL}/login", json={
        "username": "testuser",
        "password": "testpass"
    })
    assert login_response.status_code == 200
    assert "dashboard" in login_response.text or "Welcome" in login_response.text

from flask import Flask
from routes.dashboard import dashboard_bp
from routes.auth import auth_bp
from routes.monitoring import monitoring_bp
import webbrowser
import threading

app = Flask(__name__)
app.secret_key = "dev_secret"

# Register Blueprints
app.register_blueprint(dashboard_bp)
app.register_blueprint(monitoring_bp)
app.register_blueprint(auth_bp)

if __name__ == "__main__":
    # פותח את הדפדפן אחרי הפעלה
    def open_browser():
        webbrowser.open_new("http://127.0.0.1:5000/login")

    # מחכה שניה ופותח דפדפן
    threading.Timer(1, open_browser).start()

    app.run(debug=True)
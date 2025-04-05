from flask import Flask
from routes.dashboard import dashboard_bp
from routes.auth import auth_bp
from routes.monitoring import monitoring_bp

app = Flask(__name__)
app.secret_key = "dev_secret"

# Register Blueprints
app.register_blueprint(dashboard_bp)
app.register_blueprint(monitoring_bp)
app.register_blueprint(auth_bp)

if __name__ == '__main__':
    app.run(debug=True)
from flask import Flask, request, render_template, flash, redirect, url_for, session
from flask_login import LoginManager, UserMixin, login_user, login_required, current_user
import bcrypt
import pyotp
import qrcode
import io
import base64
import json
from config import load_config, save_config, get_user_data, save_user_data
from db import redis_client
from device_manager import refresh_yolink_devices

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY", "supersecretkey")  # Load from .env

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    if get_user_data(username):
        return User(username)
    return None

# Initialize default user if no users exist
def init_default_user():
    if not redis_client.keys("user:*"):
        default_username = "admin"
        default_password = "admin123"
        hashed_password = bcrypt.generate_password_hash(default_password).decode('utf-8')
        user_data = {
            "password": hashed_password,
            "force_password_change": True
        }
        save_user_data(default_username, user_data)

init_default_user()

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        totp_code = request.form.get("totp_code")
        user_data = get_user_data(username)
        if user_data and bcrypt.check_password_hash(user_data["password"], password):
            if user_data.get("force_password_change", False):
                login_user(User(username))
                return redirect(url_for("change_password"))
            if "totp_secret" in user_data:
                if not totp_code:
                    return render_template("login.html", totp_required=True, username=username)
                totp = pyotp.TOTP(user_data["totp_secret"])
                if not totp.verify(totp_code):
                    flash("Invalid TOTP code", "error")
                    return render_template("login.html", totp_required=True, username=username)
            else:
                login_user(User(username))
                return redirect(url_for("setup_totp"))
            login_user(User(username))
            return redirect(url_for("index"))
        flash("Invalid credentials", "error")
    return render_template("login.html", totp_required=False)

@app.route("/change_password", methods=["GET", "POST"])
@login_required
def change_password():
    user_data = get_user_data(current_user.id)
    if request.method == "POST":
        current_password = request.form["current_password"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        if not bcrypt.check_password_hash(user_data["password"], current_password):
            flash("Current password is incorrect", "error")
        elif new_password != confirm_password:
            flash("New passwords do not match", "error")
        elif len(new_password) < 8:
            flash("Password must be at least 8 characters", "error")
        else:
            user_data["password"] = bcrypt.generate_password_hash(new_password).decode('utf-8')
            user_data["force_password_change"] = False
            save_user_data(current_user.id, user_data)
            if "totp_secret" not in user_data:
                return redirect(url_for("setup_totp"))
            flash("Password changed successfully", "success")
            return redirect(url_for("index"))
    return render_template("change_password.html")

@app.route("/setup_totp", methods=["GET", "POST"])
@login_required
def setup_totp():
    user_data = get_user_data(current_user.id)
    if "totp_secret" in user_data:
        flash("TOTP already set up", "info")
        return redirect(url_for("index"))
    if request.method == "POST":
        totp_code = request.form["totp_code"]
        totp_secret = session.get("totp_secret")
        if not totp_secret:
            flash("Session expired, please try again", "error")
            return redirect(url_for("setup_totp"))
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
            user_data["totp_secret"] = totp_secret
            save_user_data(current_user.id, user_data)
            session.pop("totp_secret", None)
            flash("TOTP setup complete", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid TOTP code", "error")
    totp_secret = pyotp.random_base32()
    session["totp_secret"] = totp_secret
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(current_user.id, issuer_name="YoLink-CHEKT")
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_img = base64.b64encode(buffered.getvalue()).decode("utf-8")
    return render_template("setup_totp.html", qr_img=qr_img)

@app.route("/")
@login_required
def index():
    return render_template("index.html")

@app.route("/config", methods=["GET", "POST"])
@login_required
def config():
    config_data = load_config()
    if request.method == "POST":
        # Simplified: assume form data matches config structure
        new_config = json.loads(request.form["config_json"])
        save_config(new_config)
        flash("Configuration saved", "success")
        return redirect(url_for("config"))
    return render_template("config.html", config=config_data)

@app.route("/refresh_devices")
@login_required
def refresh_devices():
    refresh_yolink_devices()  # From device_manager.py
    flash("Devices refreshed successfully", "success")
    return redirect(url_for("index"))

@app.route("/")
@login_required
def index():
    user_data = get_user_data(current_user.id)
    if user_data.get("force_password_change", False):
        flash("Please change your default password.", "warning")
        return redirect(url_for("change_password"))
    devices = get_all_devices()  # Fetch from Redis
    mappings = get_mappings().get("mappings", [])
    device_mappings = {m["yolink_device_id"]: m for m in mappings}
    for device in devices:
        device["mapping"] = device_mappings.get(device["deviceId"], {})
    return render_template("index.html", devices=devices)

@app.route("/create_user", methods=["POST"])
@login_required
def create_user():
    username = request.form["username"]
    password = request.form["password"]
    if not username or not password:
        flash("Username and password required", "error")
        return redirect(url_for("config"))
    if get_user_data(username):
        flash("Username already exists", "error")
    else:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user_data = {"password": hashed_password, "force_password_change": True}
        save_user_data(username, user_data)
        flash("User created successfully", "success")
    return redirect(url_for("config"))

if __name__ == "__main__":
    app.run(debug=True)
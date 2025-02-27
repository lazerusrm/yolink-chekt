from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bcrypt import Bcrypt
import threading
import secrets
import logging
import pyotp
import qrcode
import io
import base64
from datetime import datetime

from config import load_config, save_config, config_data
from device_manager import load_devices_to_redis, get_all_devices, get_device_data
from mappings import load_mappings_to_redis, get_mappings, get_mapping
from yolink_mqtt import run_mqtt_client
from monitor_mqtt import initialize_monitor_mqtt_client
from db import redis_client

yolink_mqtt_status = {'connected': False}
monitor_mqtt_status = {'connected': False}

# Logging setup
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger()

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, username):
        self.id = username

@login_manager.user_loader
def load_user(username):
    return User(username) if username in config_data.get('users', {}) else None

@app.route('/')
@login_required
def index():
    devices = get_all_devices()
    mappings = get_mappings().get('mappings', {})
    device_mappings = {m['yolink_device_id']: m for m in mappings}
    return render_template('index.html', devices=devices, mappings=device_mappings, config=config_data)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        totp_code = request.form.get('totp_code')
        users = config_data.get('users', {})
        if username in users and bcrypt.check_password_hash(users[username]['password'], password):
            if users[username].get('totp_secret') and not totp_code:
                return render_template('login.html', totp_required=True, username=username, password=password)
            if totp_code and users[username].get('totp_secret'):
                totp = pyotp.TOTP(users[username]['totp_secret'])
                if not totp.verify(totp_code):
                    flash('Invalid TOTP code', 'error')
                    return render_template('login.html', totp_required=True, username=username, password=password)
            login_user(User(username))
            return redirect(url_for('index'))
        flash('Invalid credentials', 'error')
    return render_template('login.html', totp_required=False)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/setup_totp', methods=['GET', 'POST'])
@login_required
def setup_totp():
    if request.method == 'POST':
        totp_code = request.form['totp_code']
        totp_secret = session.get('totp_secret')
        totp = pyotp.TOTP(totp_secret)
        if totp.verify(totp_code):
            config_data['users'][current_user.id]['totp_secret'] = totp_secret
            save_config()
            session.pop('totp_secret', None)
            flash('TOTP setup complete', 'success')
            return redirect(url_for('index'))
        flash('Invalid TOTP code', 'error')
    totp_secret = pyotp.random_base32()
    session['totp_secret'] = totp_secret
    totp_uri = pyotp.TOTP(totp_secret).provisioning_uri(current_user.id, issuer_name="YoLink-CHEKT")
    img = qrcode.make(totp_uri)
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_img = base64.b64encode(buffered.getvalue()).decode('utf-8')
    return render_template('setup_totp.html', qr_img=qr_img)

@app.route('/create_user', methods=['POST'])
@login_required
def create_user():
    username = request.form['username']
    password = request.form['password']
    if username not in config_data.get('users', {}):
        config_data.setdefault('users', {})[username] = {
            'password': bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
        }
        save_config()
        flash('User created successfully', 'success')
    else:
        flash('Username already exists', 'error')
    return redirect(url_for('config'))

@app.route('/config', methods=['GET', 'POST'])
@login_required
def config():
    if request.method == 'POST':
        save_config({
            'yolink': {
                'url': request.form['yolink_url'],
                'csid': request.form['yolink_csid'],
                'csseckey': request.form['yolink_csseckey'],
                'token': request.form.get('yolink_token', '')
            },
            'chekt': {'api_token': request.form['chekt_api_token']},
            'mqtt': {
                'url': request.form['mqtt_url'],
                'port': int(request.form['mqtt_port']),
                'topic': request.form['mqtt_topic'],
                'username': request.form['yolink_username'],
                'password': request.form['yolink_password']
            },
            'mqtt_monitor': {
                'url': request.form['mqtt_monitor_url'],
                'port': int(request.form['mqtt_monitor_port']),
                'username': request.form['monitor_mqtt_username'],
                'password': request.form['monitor_mqtt_password']
            },
            'receiver_type': request.form['receiver_type'],
            'sia': {
                'ip': request.form['sia_ip'],
                'port': request.form['sia_port'],
                'account_id': request.form['sia_account_id'],
                'transmitter_id': request.form['sia_transmitter_id'],
                'contact_id': request.form['sia_contact_id'],
                'encryption_key': request.form['sia_encryption_key']
            },
            'monitor': {'api_key': request.form['monitor_api_key']},
            'timezone': request.form['timezone']
        })
        flash('Configuration saved', 'success')
        return redirect(url_for('config'))
    return render_template('config.html', config=config_data)

@app.route('/get_logs', methods=['GET'])
@login_required
def get_logs():
    try:
        with open('/app/logs/application.log', 'r') as f:
            logs = f.read()
        return jsonify({"status": "success", "logs": logs})
    except FileNotFoundError:
        return jsonify({"status": "error", "message": "Log file not found"})

@app.route('/check_receiver_status')
@login_required
def check_receiver_status():
    receiver_type = config_data.get('receiver_type', 'CHEKT')
    if receiver_type == 'CHEKT':
        return check_chekt_status()
    else:  # SIA
        sia_config = config_data.get('sia', {})
        try:
            with socket.create_connection((sia_config['ip'], int(sia_config['port'])), timeout=5):
                return jsonify({"status": "success", "message": "SIA server is alive."})
        except Exception as e:
            return jsonify({"status": "error", "message": f"Failed to connect to SIA server: {str(e)}"})

@app.route('/save_mapping', methods=['POST'])
@login_required
def save_mapping():
    mappings = get_mappings().get('mappings', [])
    new_mapping = {
        'yolink_device_id': request.form['yolink_device_id'],
        'chekt_zone': request.form.get('chekt_zone', ''),
        'sia_zone': request.form.get('sia_zone', '')
    }
    mappings = [m for m in mappings if m['yolink_device_id'] != new_mapping['yolink_device_id']]
    mappings.append(new_mapping)
    redis_client.set('mappings', json.dumps({'mappings': mappings}))
    flash('Mapping saved', 'success')
    return redirect(url_for('index'))

@app.route('/get_sensor_data/<device_id>')
@login_required
def get_sensor_data(device_id):
    device = get_device_data(device_id)
    return jsonify(device or {'error': 'Device not found'})

@app.route('/system_uptime')
@login_required
def system_uptime():
    uptime_seconds = time.time() - redis_client.info()['uptime_in_seconds']
    return jsonify({'uptime_seconds': uptime_seconds})

def refresh_yolink_token():
    url = "https://api.yosmart.com/open/yolink/token"
    data = {
        "grant_type": "client_credentials",
        "client_id": config_data['yolink']['csid'],
        "client_secret": config_data['yolink']['csseckey']
    }
    response = requests.post(url, data=data)
    if response.status_code == 200:
        token_data = response.json()
        config_data['yolink']['token'] = token_data['access_token']
        config_data['yolink']['token_expiry'] = time.time() + token_data['expires_in'] - 60
        save_config()
        return True
    return False

@app.route('/refresh_yolink_devices')
@login_required
def refresh_yolink_devices():
    if refresh_yolink_token():
        # Additional device refresh logic here
        return jsonify({"status": "success", "message": "YoLink devices refreshed"})
    return jsonify({"status": "error", "message": "Token refresh failed"})

if __name__ == "__main__":
    load_config()
    try:
        redis_client.ping()
    except redis.ConnectionError:
        logger.error("Redis not available. Exiting.")
        exit(1)
    load_devices_to_redis()
    load_mappings_to_redis()
    mqtt_thread = threading.Thread(target=run_mqtt_client, daemon=True)
    mqtt_thread.start()
    initialize_monitor_mqtt_client()
    app.run(host='0.0.0.0', port=5000)
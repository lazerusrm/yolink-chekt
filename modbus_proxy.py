import os
import socket
import threading
import logging
import time
import json
from flask import Flask, request, jsonify

# Setup logging
logging.basicConfig(level=logging.DEBUG,
                    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# Global configuration with environment variable overrides
modbus_proxy_config = {
    "target_ip": os.getenv("TARGET_IP", "127.0.0.1"),
    "target_port": int(os.getenv("TARGET_PORT", 502)),
    "listen_port": int(os.getenv("LISTEN_PORT", 1502)),
    "api_port": int(os.getenv("API_PORT", 5000)),  # Separate port for Flask API
    "enabled": os.getenv("ENABLED", "true").lower() == "true",
    "active_connections": 0
}

# Socket for listening
server_socket = None
proxy_thread = None
api_thread = None
running = False

# Create the Flask app
app = Flask(__name__)


def forward_data(source, destination, description):
    """Forward data between source and destination sockets"""
    try:
        while True:
            try:
                data = source.recv(4096)
                if not data:
                    break
                destination.sendall(data)
            except socket.timeout:
                # Socket timeout, check if we should continue
                if not running:
                    break
                continue
            except Exception as e:
                logger.error(f"Error in {description} forwarding: {e}")
                break
    except Exception as e:
        logger.error(f"Exception in {description} forwarding: {e}")
    finally:
        try:
            source.close()
        except:
            pass
        try:
            destination.close()
        except:
            pass
        with threading.Lock():
            modbus_proxy_config["active_connections"] -= 1
        logger.debug(f"Connection closed. Active connections: {modbus_proxy_config['active_connections']}")


def handle_client(client_socket, client_address):
    """Handle a client connection by proxying to the target"""
    with threading.Lock():
        modbus_proxy_config["active_connections"] += 1

    logger.debug(
        f"New connection from {client_address}. Active connections: {modbus_proxy_config['active_connections']}")

    try:
        # Create connection to target
        target_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        target_socket.settimeout(10)

        try:
            target_ip = modbus_proxy_config["target_ip"]
            target_port = modbus_proxy_config["target_port"]

            logger.debug(f"Connecting to target at {target_ip}:{target_port}")
            target_socket.connect((target_ip, target_port))

            # Setup bidirectional forwarding
            client_to_target = threading.Thread(
                target=forward_data,
                args=(client_socket, target_socket, "client->target")
            )
            target_to_client = threading.Thread(
                target=forward_data,
                args=(target_socket, client_socket, "target->client")
            )

            client_to_target.daemon = True
            target_to_client.daemon = True

            client_to_target.start()
            target_to_client.start()

            # Let the threads do the forwarding
            return

        except socket.error as e:
            logger.error(f"Failed to connect to Modbus target {target_ip}:{target_port}: {e}")
            try:
                client_socket.close()
            except:
                pass
            return
    except Exception as e:
        logger.error(f"Error handling client connection: {e}")
        try:
            client_socket.close()
        except:
            pass


def proxy_server():
    """Main proxy server loop"""
    global server_socket, running

    running = True
    logger.info(f"Starting Modbus proxy server on port {modbus_proxy_config['listen_port']}")

    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind(('0.0.0.0', modbus_proxy_config['listen_port']))
        server_socket.settimeout(1)  # 1 second timeout for interruptible accepts
        server_socket.listen(5)

        while running:
            try:
                client_socket, client_address = server_socket.accept()
                # Handle each client in a separate thread
                client_thread = threading.Thread(
                    target=handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
            except socket.timeout:
                # This allows checking the running flag periodically
                continue
            except Exception as e:
                if running:  # Only log if we're still supposed to be running
                    logger.error(f"Error accepting connection: {e}")

        logger.info("Modbus proxy server stopped")
    except Exception as e:
        logger.error(f"Error in proxy server: {e}")
    finally:
        if server_socket:
            try:
                server_socket.close()
            except:
                pass


def start_proxy():
    """Start the proxy server in a background thread"""
    global proxy_thread, running

    if proxy_thread and proxy_thread.is_alive():
        logger.info("Proxy already running")
        return

    running = True
    proxy_thread = threading.Thread(target=proxy_server)
    proxy_thread.daemon = True
    proxy_thread.start()
    logger.info("Started Modbus proxy thread")


def stop_proxy():
    """Stop the proxy server"""
    global running, server_socket

    logger.info("Stopping Modbus proxy server")
    running = False

    # Close the server socket to interrupt accept()
    if server_socket:
        try:
            server_socket.close()
        except:
            pass

    if proxy_thread:
        proxy_thread.join(timeout=5)
        if proxy_thread.is_alive():
            logger.warning("Proxy thread did not terminate cleanly")


def restart_proxy():
    """Restart the proxy with new settings"""
    stop_proxy()
    time.sleep(1)  # Give it time to shut down
    start_proxy()


# Flask routes for the proxy API
@app.route('/api/modbus-proxy/configure', methods=['POST'])
def api_configure_proxy():
    """Configure the Modbus proxy via API"""
    try:
        data = request.get_json()
        logger.debug(f"Received proxy configuration: {data}")

        if not data:
            return jsonify({"status": "error", "message": "Invalid request data"}), 400

        # Update configuration
        restart_needed = False

        if "target_ip" in data:
            modbus_proxy_config["target_ip"] = data["target_ip"]
            restart_needed = True

        if "target_port" in data:
            try:
                modbus_proxy_config["target_port"] = int(data["target_port"])
                restart_needed = True
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "Invalid target port"}), 400

        if "listen_port" in data:
            try:
                new_port = int(data["listen_port"])
                if new_port != modbus_proxy_config["listen_port"]:
                    modbus_proxy_config["listen_port"] = new_port
                    restart_needed = True
            except (ValueError, TypeError):
                return jsonify({"status": "error", "message": "Invalid listen port"}), 400

        if "enabled" in data:
            enabled = bool(data["enabled"])
            if enabled != modbus_proxy_config["enabled"]:
                modbus_proxy_config["enabled"] = enabled
                if enabled:
                    start_proxy()
                else:
                    stop_proxy()

        # Restart the proxy if needed and it's enabled
        if restart_needed and modbus_proxy_config["enabled"]:
            restart_proxy()

        return jsonify({
            "status": "success",
            "config": modbus_proxy_config
        })
    except Exception as e:
        logger.error(f"Error configuring proxy: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route('/api/modbus-proxy/status', methods=['GET'])
def api_get_proxy_status():
    """Get the current status of the Modbus proxy"""
    proxy_running = proxy_thread is not None and proxy_thread.is_alive()

    return jsonify({
        "status": "success",
        "proxy_status": {
            "enabled": modbus_proxy_config["enabled"],
            "running": proxy_running,
            "target_ip": modbus_proxy_config["target_ip"],
            "target_port": modbus_proxy_config["target_port"],
            "listen_port": modbus_proxy_config["listen_port"],
            "active_connections": modbus_proxy_config["active_connections"]
        }
    })


# Simple direct endpoints for backward compatibility
@app.route('/configure', methods=['POST'])
def simple_configure_proxy():
    """Simple configure endpoint for backward compatibility"""
    logger.info("Received configuration through /configure endpoint")
    return api_configure_proxy()


@app.route('/status', methods=['GET'])
def simple_get_status():
    """Simple status endpoint for backward compatibility"""
    logger.info("Status requested through /status endpoint")
    return api_get_proxy_status()


@app.route('/healthcheck', methods=['GET'])
def healthcheck():
    """Simple health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": time.time(),
        "proxy_running": proxy_thread is not None and proxy_thread.is_alive()
    })


def start_api_server():
    """Run the Flask app in a separate thread"""
    api_port = modbus_proxy_config["api_port"]
    logger.info(f"Starting API server on port {api_port}")
    try:
        app.run(host='0.0.0.0', port=api_port, threaded=True)
    except Exception as e:
        logger.error(f"Error running API server: {e}")


def start_api():
    """Start the API server in a background thread"""
    global api_thread

    if api_thread and api_thread.is_alive():
        logger.info("API server already running")
        return

    api_thread = threading.Thread(target=start_api_server)
    api_thread.daemon = True
    api_thread.start()
    logger.info("Started API server thread")


# Initialize the proxy when the module is imported
def init():
    """Initialize both the proxy and API services"""
    # Start the Modbus TCP proxy
    if modbus_proxy_config["enabled"]:
        start_proxy()

    # Start the API server
    start_api()


# Main entry point
if __name__ == "__main__":
    try:
        # Initialize both services
        init()

        # Keep the main thread alive
        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        logger.info("Shutting down on keyboard interrupt")
        stop_proxy()
    except Exception as e:
        logger.error(f"Error in main thread: {e}")
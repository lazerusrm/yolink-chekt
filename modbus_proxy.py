import asyncio
import logging
import os
from quart import Quart, request, jsonify

# Logging setup
logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Quart app for async API
app = Quart(__name__)

# Global configuration with environment overrides
config = {
    "target_ip": os.getenv("TARGET_IP", "10.250.250.2"),  # Matches docker-compose.yml
    "target_port": int(os.getenv("TARGET_PORT", 502)),
    "listen_port": int(os.getenv("LISTEN_PORT", 1502)),
    "api_port": int(os.getenv("API_PORT", 5000)),
    "enabled": os.getenv("ENABLED", "true").lower() == "true",
    "active_connections": 0
}

# Global server reference
server = None

async def forward(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Forward data between two streams asynchronously."""
    try:
        while True:
            data = await reader.read(4096)
            if not data:
                break
            writer.write(data)
            await writer.drain()
    except Exception as e:
        logger.error(f"Forwarding error: {e}")
    finally:
        writer.close()
        await writer.wait_closed()

async def handle_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    """Handle a client connection by proxying to the target."""
    config["active_connections"] += 1
    client_addr = writer.get_extra_info('peername')
    logger.debug(f"New connection from {client_addr}. Active: {config['active_connections']}")

    try:
        target_reader, target_writer = await asyncio.open_connection(
            config["target_ip"], config["target_port"]
        )
        await asyncio.gather(
            forward(reader, target_writer),
            forward(target_reader, writer)
        )
    except Exception as e:
        logger.error(f"Failed to connect to target {config['target_ip']}:{config['target_port']}: {e}")
        writer.close()
        await writer.wait_closed()
    finally:
        config["active_connections"] -= 1
        logger.debug(f"Connection closed. Active: {config['active_connections']}")

async def proxy_server() -> None:
    """Run the async Modbus proxy server."""
    global server
    try:
        server = await asyncio.start_server(handle_client, '0.0.0.0', config["listen_port"])
        logger.info(f"Modbus proxy started on 0.0.0.0:{config['listen_port']}")
        async with server:
            await server.serve_forever()
    except Exception as e:
        logger.error(f"Proxy server error: {e}")
    finally:
        if server:
            server.close()
            await server.wait_closed()
            logger.info("Proxy server stopped")

@app.route('/api/modbus-proxy/configure', methods=['POST'])
async def configure_proxy():
    """Configure the proxy via API."""
    try:
        data = await request.get_json()
        if not data:
            return jsonify({"status": "error", "message": "Invalid data"}), 400

        if "target_ip" in data:
            config["target_ip"] = data["target_ip"]
        if "target_port" in data:
            config["target_port"] = int(data["target_port"])
        if "enabled" in data:
            config["enabled"] = bool(data["enabled"])

        logger.info(f"Proxy configured: {config}")
        return jsonify({"status": "success", "config": config})
    except Exception as e:
        logger.error(f"Configuration error: {e}")
        return jsonify({"status": "error", "message": str(e)}), 500

@app.route('/api/modbus-proxy/status', methods=['GET'])
async def get_status():
    """Return proxy status."""
    return jsonify({
        "status": "success",
        "proxy_status": {
            "enabled": config["enabled"],
            "running": server is not None and server.is_serving(),
            "target_ip": config["target_ip"],
            "target_port": config["target_port"],
            "listen_port": config["listen_port"],
            "active_connections": config["active_connections"]
        }
    })

@app.route('/healthcheck', methods=['GET'])
async def healthcheck():
    """Simple health check."""
    import time
    return jsonify({
        "status": "healthy",
        "timestamp": time.time(),
        "proxy_running": server is not None and server.is_serving()
    })

async def main():
    """Run both proxy and API."""
    if config["enabled"]:
        await asyncio.gather(
            proxy_server(),
            app.run_task(host='0.0.0.0', port=config["api_port"], debug=False)
        )
    else:
        logger.info("Proxy disabled, running API only")
        await app.run_task(host='0.0.0.0', port=config["api_port"], debug=False)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Shutting down")
    except Exception as e:
        logger.error(f"Main error: {e}")
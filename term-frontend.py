"""
Terminal Frontend Utility - Async Version
=======================================

A command-line interface for testing and troubleshooting the YoLink integration.
"""

import os
import threading
import asyncio
import logging
from time import sleep
import aiohttp
import nest_asyncio

# Enable nested event loops for asyncio in interactive environments
nest_asyncio.apply()

# Import the async config loader
from config import load_config
from redis_manager import get_redis, ensure_connection

# Adjust based on your logging setup
log_file_path = '/app/logs/app.log'


def display_logs():
    """Displays logs in real-time"""
    if not os.path.exists(log_file_path):
        print(f"Log file {log_file_path} not found.")
        return

    with open(log_file_path, 'r') as f:
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if line:
                print(line.strip())
            else:
                sleep(0.1)


async def test_redis_connection():
    """Test the Redis connection"""
    print("\nTesting Redis Connection...\n")
    try:
        # Get Redis client and test connection
        redis_client = await get_redis()
        ping_result = await redis_client.ping()

        if ping_result:
            print("✓ Redis connection successful!")

            # Get some stats
            info = await redis_client.info()
            print(f"Redis version: {info.get('redis_version', 'Unknown')}")
            print(f"Connected clients: {info.get('connected_clients', 'Unknown')}")
            print(f"Memory used: {info.get('used_memory_human', 'Unknown')}")

            # Check for device keys
            device_keys = await redis_client.keys("device:*")
            print(f"Found {len(device_keys)} device keys in Redis")

            if device_keys:
                # Show a sample device
                sample_device_json = await redis_client.get(device_keys[0])
                print(f"Sample device data: {sample_device_json[:100]}...")

        else:
            print("✗ Redis ping failed")
    except Exception as e:
        print(f"✗ Redis connection error: {e}")


async def test_yolink_api():
    """Test the YoLink API connection"""
    print("\nTesting YoLink API...\n")

    try:
        # Get the config data using async load_config() function
        config = await load_config()
        yolink_config = config.get('yolink', {})

        if not yolink_config.get('token'):
            print("✗ No YoLink token found in configuration")
            from device_manager import get_access_token
            token = await get_access_token(config)
            if token:
                print(f"✓ Generated new token: {token[:10]}...")
                yolink_config['token'] = token
            else:
                print("✗ Failed to generate YoLink token")
                return

        # Test API with access token
        url = "https://api.yosmart.com/open/yolink/v2/api"
        headers = {'Authorization': f"Bearer {yolink_config['token']}"}
        data = {"method": "Home.getGeneralInfo"}

        async with aiohttp.ClientSession() as session:
            async with session.post(url, headers=headers, json=data) as response:
                status = response.status
                response_json = await response.json()

                print(f"Status Code: {status}")
                if status == 200 and response_json.get('code') == '000000':
                    print("✓ YoLink API connection successful!")
                    print(f"Home Name: {response_json.get('data', {}).get('name', 'Unknown')}")
                    print(f"Home ID: {response_json.get('data', {}).get('id', 'Unknown')}")
                else:
                    print(
                        f"✗ YoLink API error: {response_json.get('code')} - {response_json.get('desc', 'Unknown error')}")
    except Exception as e:
        print(f"✗ YoLink API test error: {e}")


async def test_chekt_api():
    """Test the CHEKT API connection"""
    print("\nTesting CHEKT API...\n")

    try:
        # Get the config data using async load_config() function
        config = await load_config()
        chekt_config = config.get('chekt', {})

        if not chekt_config.get('enabled', True):
            print("✗ CHEKT integration is disabled in configuration")
            return

        if not chekt_config.get('api_token') or not chekt_config.get('ip') or not chekt_config.get('port'):
            print("✗ Incomplete CHEKT configuration")
            print(f"  API Token: {'✓ Set' if chekt_config.get('api_token') else '✗ Missing'}")
            print(f"  IP Address: {'✓ ' + chekt_config.get('ip') if chekt_config.get('ip') else '✗ Missing'}")
            print(f"  Port: {'✓ ' + str(chekt_config.get('port')) if chekt_config.get('port') else '✗ Missing'}")
            return

        # Test a simple health check endpoint (you may need to adjust this based on CHEKT API)
        url = f"http://{chekt_config['ip']}:{chekt_config['port']}/api/v1/health"
        headers = {'Authorization': f"Basic {chekt_config['api_token']}"}

        async with aiohttp.ClientSession() as session:
            try:
                async with session.get(url, headers=headers, timeout=5) as response:
                    status = response.status
                    response_text = await response.text()

                    print(f"Status Code: {status}")
                    if status == 200:
                        print("✓ CHEKT API connection successful!")
                        print(f"Response: {response_text[:100]}")
                    else:
                        print(f"✗ CHEKT API returned error status: {status}")
                        print(f"Response: {response_text[:100]}")
            except aiohttp.ClientConnectorError:
                print(f"✗ Failed to connect to CHEKT at {chekt_config['ip']}:{chekt_config['port']}")
                print("  Please check if the CHEKT receiver is online and accessible")
    except Exception as e:
        print(f"✗ CHEKT API test error: {e}")


async def test_modbus():
    """Test the Modbus connection"""
    print("\nTesting Modbus Connection...\n")

    try:
        # Import Modbus modules
        import modbus_relay

        # Get configuration
        config = await load_config()
        modbus_config = config.get('modbus', {})

        if not modbus_config.get('enabled', False):
            print("✗ Modbus integration is disabled in configuration")
            return

        # Test Modbus connection
        print("Attempting to initialize Modbus relay...")
        success = await modbus_relay.initialize()

        if success:
            print("✓ Modbus initialization successful!")

            # Test probe
            max_channels = modbus_config.get('max_channels', 8)
            print(f"Testing {max_channels} relay channels...")

            test_results = await modbus_relay.test_channels(max_channels)

            print(f"Test Status: {test_results['status']}")
            print(f"Message: {test_results['message']}")

            for result in test_results.get('results', []):
                status_icon = "✓" if result.get('success') else "✗"
                print(f"{status_icon} Channel {result.get('channel')}: {result.get('message')}")
        else:
            print("✗ Modbus initialization failed")
    except Exception as e:
        print(f"✗ Modbus test error: {e}")


async def test_mqtt():
    """Test MQTT connections"""
    print("\nTesting MQTT Connections...\n")

    try:
        # Test YoLink MQTT
        print("Checking YoLink MQTT status...")
        from yolink_mqtt import get_status as get_yolink_status
        yolink_status = await get_yolink_status()

        if yolink_status.get('connected', False):
            print("✓ YoLink MQTT is connected")
            if yolink_status.get('last_connected'):
                import time
                connected_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                               time.localtime(yolink_status['last_connected']))
                print(f"  Connected since: {connected_time}")
        else:
            print(f"✗ YoLink MQTT is not connected: {yolink_status.get('status', 'unknown')}")
            if yolink_status.get('error'):
                print(f"  Error: {yolink_status['error']}")

        # Test Monitor MQTT
        print("\nChecking Monitor MQTT status...")
        from monitor_mqtt import get_status as get_monitor_status
        monitor_status = await get_monitor_status()

        if monitor_status.get('connected', False):
            print("✓ Monitor MQTT is connected")
            if monitor_status.get('last_connected'):
                import time
                connected_time = time.strftime('%Y-%m-%d %H:%M:%S',
                                               time.localtime(monitor_status['last_connected']))
                print(f"  Connected since: {connected_time}")
        else:
            print(f"✗ Monitor MQTT is not connected: {monitor_status.get('status', 'unknown')}")
            if monitor_status.get('error'):
                print(f"  Error: {monitor_status['error']}")
    except Exception as e:
        print(f"✗ MQTT test error: {e}")


async def show_device_info():
    """Show information about connected devices"""
    print("\nRetrieving Device Information...\n")

    try:
        from device_manager import get_all_devices
        redis_client = await get_redis()
        devices = await get_all_devices(redis_client)

        if not devices:
            print("No devices found in Redis")
            return

        print(f"Found {len(devices)} devices:")
        print("\n" + "=" * 50)

        for idx, device in enumerate(devices, 1):
            name = device.get('name', 'Unknown')
            device_id = device.get('deviceId', 'Unknown')
            device_type = device.get('type', 'Unknown')
            state = device.get('state', 'Unknown')
            battery = device.get('battery', 'N/A')
            signal = device.get('signal', 'N/A')
            last_seen = device.get('last_seen', 'Never')

            print(f"{idx}. {name} ({device_type})")
            print(f"   ID: {device_id}")
            print(f"   State: {state}")
            print(f"   Battery: {battery}")
            print(f"   Signal: {signal}")
            print(f"   Last Seen: {last_seen}")
            print("=" * 50)
    except Exception as e:
        print(f"Error retrieving device information: {e}")


async def async_menu():
    """Async menu for running tests"""
    while True:
        print("\nYoLink Integration Troubleshooting Menu:")
        print("1. Test Redis Connection")
        print("2. Test YoLink API")
        print("3. Test CHEKT API")
        print("4. Test Modbus")
        print("5. Test MQTT Connections")
        print("6. Show Device Information")
        print("7. Exit")

        choice = input("Select an option (1-7): ")

        if choice == "1":
            await test_redis_connection()
        elif choice == "2":
            await test_yolink_api()
        elif choice == "3":
            await test_chekt_api()
        elif choice == "4":
            await test_modbus()
        elif choice == "5":
            await test_mqtt()
        elif choice == "6":
            await show_device_info()
        elif choice == "7":
            print("Exiting...")
            break
        else:
            print("Invalid choice, please select a valid option.")

        input("\nPress Enter to continue...")


def menu():
    """Synchronous wrapper for the async menu"""
    asyncio.run(async_menu())


if __name__ == "__main__":
    # Run the log display in a separate thread
    log_thread = threading.Thread(target=display_logs, daemon=True)
    log_thread.start()

    # Run the menu (will invoke async functions)
    menu()
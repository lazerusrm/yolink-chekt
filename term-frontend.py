import os
import threading
from time import sleep
import logging
from config import config_data
from yolink_mqtt import run_mqtt_client
import requests

log_file_path = '/app/logs/application.log'  # Adjust based on your logging setup


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


def test_yolink_api():
    """Test the YoLink API connection"""
    print("\nRunning YoLink API Test...\n")
    yolink_config = config_data.get('yolink', {})
    url = f"{yolink_config['url']}/api/v3/devices"
    headers = {'Authorization': f"Bearer {yolink_config['token']}"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {str(e)}")


def test_chekt_api():
    """Test the CHEKT API connection"""
    print("\nRunning CHEKT API Test...\n")
    chekt_config = config_data.get('chekt', {})
    url = "https://api.chekt.com/v1/test"  # Replace with actual CHEKT API endpoint
    headers = {'Authorization': f"Bearer {chekt_config['api_token']}"}
    try:
        response = requests.get(url, headers=headers, timeout=5)
        print(f"Status: {response.status_code}")
        print(f"Response: {response.json()}")
    except Exception as e:
        print(f"Error: {str(e)}")


def test_mqtt():
    """Test MQTT connection"""
    print("\nAttempting MQTT Connection...\n")
    try:
        mqtt_thread = threading.Thread(target=run_mqtt_client, daemon=True)
        mqtt_thread.start()
        sleep(2)  # Give it time to connect
        print("MQTT client started successfully.")
    except Exception as e:
        print(f"Error: {str(e)}")


def menu():
    """Simple text-based menu for running tests"""
    while True:
        print("\nYoLink-CHEKT Troubleshooting Menu:")
        print("1. Test YoLink API")
        print("2. Test CHEKT API")
        print("3. Test MQTT Connection")
        print("4. Exit")

        choice = input("Select an option (1-4): ")

        if choice == "1":
            test_yolink_api()
        elif choice == "2":
            test_chekt_api()
        elif choice == "3":
            test_mqtt()
        elif choice == "4":
            print("Exiting...")
            break
        else:
            print("Invalid choice, please select a valid option.")


if __name__ == "__main__":
    # Run the log display in a separate thread
    log_thread = threading.Thread(target=display_logs, daemon=True)
    log_thread.start()
    menu()
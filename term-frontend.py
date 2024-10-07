import os
import subprocess
import threading
from prompt_toolkit import button_dialog
from time import sleep
import app  # Import your app.py module
import logging

log_file_path = 'application.log'  # The log file path used in app.py

def display_logs():
    """Displays logs in real-time"""
    with open(log_file_path, 'r') as f:
        f.seek(0, os.SEEK_END)  # Move to end of file
        while True:
            line = f.readline()
            if line:
                print(line.strip())
            else:
                sleep(0.1)  # Poll every 0.1 seconds

def test_yolink_api():
    """Test the YoLink API and display result"""
    print("\nRunning YoLink API Test...\n")
    response = app.test_yolink_api()
    print(response)

def test_chekt_api():
    """Test the CHEKT API and display result"""
    print("\nRunning CHEKT API Test...\n")
    response = app.test_chekt_api()
    print(response)

def test_mqtt():
    """Test MQTT connection and display result"""
    print("\nAttempting MQTT Connection...\n")
    try:
        # This runs the MQTT client connection as defined in app.py
        app.run_mqtt_client()  
    except Exception as e:
        print(f"Error: {str(e)}")

def menu():
    """Main menu for running tests"""
    while True:
        choice = button_dialog(
            title="YoLink-CHEKT Troubleshooting",
            text="Select a test to run:",
            buttons=[
                ("Test YoLink API", 1),
                ("Test CHEKT API", 2),
                ("Test MQTT Connection", 3),
                ("Exit", 4),
            ],
        ).run()

        if choice == 1:
            test_yolink_api()
        elif choice == 2:
            test_chekt_api()
        elif choice == 3:
            test_mqtt()
        elif choice == 4:
            break

if __name__ == "__main__":
    # Run the log display in a separate thread
    log_thread = threading.Thread(target=display_logs, daemon=True)
    log_thread.start()

    # Display the main menu for running tests
    menu()

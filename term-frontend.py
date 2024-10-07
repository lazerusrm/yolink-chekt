import os
import threading
from time import sleep
import app  # Import your app.py module

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
    print("\nRunning YoLink API Test...\n")
    response = yolink_api_test()  # Directly call the test function from app.py
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

    # Display the main menu for running tests
    menu()

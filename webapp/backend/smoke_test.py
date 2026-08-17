import os
import time
import requests
from requests.exceptions import ConnectionError

API_URL = os.environ.get("API_URL", "http://localhost:8000")
ADMIN_USER = "testadmin"
ADMIN_PASS = "testpass"

def wait_for_backend():
    print(f"Waiting for backend at {API_URL}...")
    for _ in range(30):
        try:
            r = requests.get(f"{API_URL}/api/health")
            if r.status_code == 200:
                print("Backend is up!")
                return True
        except ConnectionError:
            pass
        time.sleep(1)
    print("Backend failed to start.")
    return False

def test_login():
    print("Testing admin login...")
    r = requests.post(f"{API_URL}/api/auth/login", json={"username": ADMIN_USER, "password": ADMIN_PASS})
    if r.status_code == 200:
        print("Login SUCCESS")
        return r.cookies.get("access_token")
    else:
        print(f"Login FAILED: {r.text}")
        return None

def test_admin_authorization(token):
    print("Testing admin authorization...")
    r = requests.get(f"{API_URL}/api/auth/users", cookies={"access_token": token})
    if r.status_code == 200:
        print("Admin access SUCCESS (fetched users)")
        return True
    else:
        print(f"Admin access FAILED: {r.text}")
        return False

def test_scan_creation_and_cancellation(token):
    print("Testing scan creation...")
    r = requests.post(f"{API_URL}/api/scans", json={"target": "example.com", "authorized": True}, cookies={"access_token": token})
    if not r.ok:
        print(f"Scan creation FAILED: {r.text}")
        return False
    
    scan_id = r.json()["id"]
    print(f"Scan creation SUCCESS. ID: {scan_id}")
    
    print("Testing scan cancellation...")
    r = requests.post(f"{API_URL}/api/scans/{scan_id}/cancel", cookies={"access_token": token})
    if r.status_code == 200:
        print("Scan cancellation SUCCESS")
        return True
    else:
        print(f"Scan cancellation FAILED: {r.text}")
        return False

def run_tests():
    if not wait_for_backend():
        return
    
    print("Bootstrapping admin user for test...")
    os.system(f"./.venv/bin/python create_admin.py {ADMIN_USER} {ADMIN_PASS} > /dev/null")
    
    token = test_login()
    if not token:
        return
    
    if not test_admin_authorization(token):
        return
        
    if not test_scan_creation_and_cancellation(token):
        return
        
    print("All tests passed.")

if __name__ == "__main__":
    run_tests()

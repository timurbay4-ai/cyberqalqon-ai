import os
import sys
import json
import time
import subprocess
import urllib.request
from urllib.error import HTTPError, URLError

BACKEND_URL = "http://127.0.0.1:8001" # use different port to avoid conflicts
API_TOKEN = "test-api-token-secret-12345"
WAZUH_TOKEN = "test-wazuh-token-secret-67890"

def run_test(name, req):
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            body = resp.read().decode('utf-8')
            return resp.status, body
    except HTTPError as e:
        body = e.read().decode('utf-8')
        return e.code, body
    except URLError as e:
        return 0, str(e.reason)

def main():
    print("--- Starting M3 Authentication Tests ---")
    
    # Test A: Protected Ingestion with Correct Token
    print("Test A: Protected ingestion (valid WAZUH token)")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/ingest/wazuh",
        data=b'{"rule": {"id": "1", "level": 10}, "agent": {"name": "test"}}',
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {WAZUH_TOKEN}"},
        method="POST"
    )
    status, body = run_test("Test A", req)
    print(f"Result: {status}")
    if status not in (201, 200):
        print(f"Failed Test A: Expected 201/200, got {status} - {body}")
        sys.exit(1)
        
    incident_data = json.loads(body)
    incident_id = incident_data.get("id")

    # Test B: Missing Token
    print("Test B: Missing token for ingestion")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/ingest/wazuh",
        data=b'{"rule": {"id": "1", "level": 10}, "agent": {"name": "test"}}',
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    status, body = run_test("Test B", req)
    print(f"Result: {status}")
    if status != 401:
        print(f"Failed Test B: Expected 401, got {status} - {body}")
        sys.exit(1)
        
    # Test C: Incorrect Token
    print("Test C: Incorrect token for ingestion")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/ingest/wazuh",
        data=b'{"rule": {"id": "1", "level": 10}, "agent": {"name": "test"}}',
        headers={"Content-Type": "application/json", "Authorization": "Bearer wrong-token"},
        method="POST"
    )
    status, body = run_test("Test C", req)
    print(f"Result: {status}")
    if status != 401:
        print(f"Failed Test C: Expected 401, got {status} - {body}")
        sys.exit(1)

    # Test D: Token Isolation
    print("Test D1: Using API token for Wazuh ingestion")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/ingest/wazuh",
        data=b'{"rule": {"id": "1", "level": 10}, "agent": {"name": "test"}}',
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_TOKEN}"},
        method="POST"
    )
    status, body = run_test("Test D1", req)
    print(f"Result: {status}")
    if status not in (401, 403):
        print(f"Failed Test D1: Expected 401/403, got {status} - {body}")
        sys.exit(1)

    print("Test D2: Using Wazuh token for API endpoint")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/incidents",
        headers={"Authorization": f"Bearer {WAZUH_TOKEN}"},
        method="GET"
    )
    status, body = run_test("Test D2", req)
    print(f"Result: {status}")
    if status not in (401, 403):
        print(f"Failed Test D2: Expected 401/403, got {status} - {body}")
        sys.exit(1)

    # Test E: Incident API protection
    print("Test E: API Endpoints with valid API token")
    for endpoint in [
        f"/api/v1/incidents",
        f"/api/v1/incidents/stats",
        f"/api/v1/incidents/{incident_id}"
    ]:
        req = urllib.request.Request(
            f"{BACKEND_URL}{endpoint}",
            headers={"Authorization": f"Bearer {API_TOKEN}"},
            method="GET"
        )
        status, body = run_test(f"Test E - {endpoint}", req)
        print(f"Endpoint {endpoint} Result: {status}")
        if status != 200:
            print(f"Failed Test E: Expected 200, got {status} - {body}")
            sys.exit(1)
            
    # Test E Review (POST)
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/incidents/{incident_id}/review",
        data=b'{"status": "confirmed", "analyst": "test"}',
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {API_TOKEN}"},
        method="POST"
    )
    status, body = run_test("Test E - Review POST", req)
    print(f"Review POST Result: {status}")
    if status != 201:
        print(f"Failed Test E Review: Expected 201, got {status} - {body}")
        sys.exit(1)

    print("Test E: Missing token on API endpoint")
    req = urllib.request.Request(
        f"{BACKEND_URL}/api/v1/incidents",
        method="GET"
    )
    status, body = run_test("Test E - Missing token", req)
    print(f"Result: {status}")
    if status != 401:
        print(f"Failed Test E Missing: Expected 401, got {status} - {body}")
        sys.exit(1)

    # Test G: Error Message Security
    print("Test G: Checking error message format for token leakage")
    if "test-api-token" in body or "test-wazuh-token" in body or "APP_ENV" in body:
        print(f"Failed Test G: Error message leaks secrets - {body}")
        sys.exit(1)
    else:
        print("Test G passed. No secrets in error messages.")

    print("--- ALL TESTS PASSED ---")

if __name__ == "__main__":
    main()

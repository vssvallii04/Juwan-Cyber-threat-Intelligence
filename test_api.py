import requests
import json
import traceback

BASE_URL = "http://127.0.0.1:8000"

def test_endpoint(path, payload):
    print(f"\n--- Testing {path} ---")
    try:
        response = requests.post(f"{BASE_URL}{path}", json=payload, timeout=10)
        print(f"Status Code: {response.status_code}")
        print(f"Content-Type: {response.headers.get('Content-Type')}")
        print(f"Response Body: {response.text}")
    except Exception as e:
        print(f"Request failed: {e}")
        traceback.print_exc()

test_endpoint("/analyze/url", {"url": "https://google.com"})
test_endpoint("/analyze/chat", {"text": "URGENT: send bitcoin to nigerian prince"})
test_endpoint("/analyze/url/apk-risk", {"url": "https://googlepool.xyz/drop.apk"})

"""
M8 Local Integration Verification
Wazuh sender v2 → Backend → Verify persistence and evidence integrity
"""
import json, os, sys, tempfile, time
import urllib.request, urllib.error

BACKEND = "http://127.0.0.1:8002"
INGEST_URL = f"{BACKEND}/api/v1/ingest/wazuh"
INCIDENTS_URL = f"{BACKEND}/api/v1/incidents"

# tests/ lives inside wazuh/tests/ — so wazuh root is one level up
WAZUH_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SAMPLES_DIR = os.path.join(WAZUH_ROOT, "samples")

def request(url, data=None, token=None, method="GET"):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        return e.code, body

results = []
def step(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    results.append((name, ok))
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))

print("\n=== M8 Local Integration Verification ===\n")

# Step 1: Load committed sample fixtures using the sender's read_alert (BOM-safe)
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "integrations"))
from cyberqalqon_sender import read_alert, post_alert  # noqa

sample_files = [f for f in os.listdir(SAMPLES_DIR) if f.endswith(".json")]
step("Sample fixtures exist", len(sample_files) >= 1, f"{len(sample_files)} files")

# Step 2: Submit first sample — authenticated (no token in dev mode)
sample_path = os.path.join(SAMPLES_DIR, "auth_failure.json")
alert = read_alert(sample_path)
step("auth_failure.json loaded (BOM-safe)", "rule" in alert)

# Submit via full sender
payload = json.dumps(alert, ensure_ascii=False).encode("utf-8")
status, body = request(INGEST_URL, data=payload, method="POST")
step("POST /api/v1/ingest/wazuh -> 2xx", status in (200, 201), f"HTTP {status}")

if status in (200, 201):
    inc = body if isinstance(body, dict) else {}
    incident_id = inc.get("id")
    step("Response has incident.id", bool(incident_id), incident_id)
    step("raw_event preserved", inc.get("raw_event") == alert,
         "raw_event matches submitted payload" if inc.get("raw_event") == alert else "MISMATCH")
    step("rule_id extracted", inc.get("rule_id") == alert["rule"]["id"])
    step("agent_name extracted", inc.get("agent_name") == alert.get("agent", {}).get("name"))

    # Step 3: Duplicate submission → deduplication
    status2, body2 = request(INGEST_URL, data=payload, method="POST")
    step("Duplicate → HTTP 200 (deduplication)", status2 == 200, f"HTTP {status2}")
    if isinstance(body2, dict):
        step("Duplicate returns same incident_id", body2.get("id") == incident_id)

    # Step 4: Retrieve via API
    status3, body3 = request(f"{INCIDENTS_URL}/{incident_id}")
    step("GET /incidents/{id} → 200", status3 == 200, f"HTTP {status3}")
    if isinstance(body3, dict):
        step("Retrieved raw_event intact", body3.get("raw_event") == alert)
        step("rule_level correct", str(body3.get("rule_level")) == str(alert["rule"]["level"]))

# Step 5: All fixtures load and submit
print("\n  --- All Fixtures Submission ---")
for fname in sample_files:
    fpath = os.path.join(SAMPLES_DIR, fname)
    a = read_alert(fpath)
    p = json.dumps(a, ensure_ascii=False).encode("utf-8")
    s, _ = request(INGEST_URL, data=p, method="POST")
    step(f"{fname} → {s}", s in (200, 201))

# Step 6: Stats endpoint
s4, stats = request(f"{BACKEND}/api/v1/incidents/stats")
step("GET /incidents/stats → 200", s4 == 200)
if isinstance(stats, dict):
    step("Stats has total > 0", stats.get("total", 0) > 0,
         f"total={stats.get('total')}")

print(f"\n=== Results: {sum(1 for _, ok in results if ok)}/{len(results)} passed ===\n")
if not all(ok for _, ok in results):
    sys.exit(1)

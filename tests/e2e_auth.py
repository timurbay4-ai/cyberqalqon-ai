import json, sys, urllib.error, urllib.request, uuid

BACKEND = "http://127.0.0.1:8099"
INGEST = BACKEND + "/api/v1/ingest/wazuh"
INCIDENTS = BACKEND + "/api/v1/incidents"
SUMMARY = INCIDENTS + "/summary"
STATS = INCIDENTS + "/stats"
API = "e2e-api-test-token-1355372796"
WAZ = "e2e-wazuh-test-token-557829557"

def req(url, data=None, token=None, method="GET"):
    h = {"Content-Type":"application/json","Accept":"application/json"}
    if token: h["Authorization"] = "Bearer " + token
    r = urllib.request.Request(url, data=data, headers=h, method=method)
    try:
        with urllib.request.urlopen(r, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as e:
        try: body = json.loads(e.read())
        except: body = str(e)
        return e.code, body
    except Exception as e:
        return 0, str(e)

results = []
def step(name, ok, detail=""):
    results.append((name, ok))
    label = "PASS" if ok else "FAIL"
    suffix = " [" + detail + "]" if detail else ""
    print(label + " | " + name + suffix)

print("=== E2E Test (Authenticated Backend, port 8099) ===")
step("API token set", bool(API))
step("WAZUH token set", bool(WAZ))
step("Tokens different", API != WAZ)

s, b = req(BACKEND + "/health")
step("Health 200", s == 200)

print("\n--- TEST A: First Ingestion ---")
tag = str(uuid.uuid4())
alert = {
    "timestamp": "2026-10-01T12:00:00.000+0000",
    "rule": {"id":"88888","level":12,"description":"E2E auth-test "+tag,
             "mitre":{"id":["T1078"],"tactic":["Defense Evasion"],"technique":["Valid Accounts"]}},
    "agent": {"id":"001","name":"e2e-agent","ip":"192.168.1.1"},
    "data": {"srcip":"10.0.0.1"}
}
payload = json.dumps(alert, ensure_ascii=False).encode("utf-8")
s, b = req(INGEST, data=payload, token=WAZ, method="POST")
step("POST /ingest/wazuh -> 201", s == 201, "HTTP " + str(s))
inc_id = None
if isinstance(b, dict):
    inc_id = b.get("id")
    step("Has incident.id", bool(inc_id))
    step("raw_event preserved", b.get("raw_event") == alert)
    step("rule_id=88888", b.get("rule_id") == "88888")
    step("agent_name=e2e-agent", b.get("agent_name") == "e2e-agent")
    step("severity=critical", b.get("severity") == "critical")
else:
    step("Response is dict", False, str(b)[:80])

print("\n--- TEST B: Duplicate ---")
s, b = req(INGEST, data=payload, token=WAZ, method="POST")
step("Duplicate -> 200", s == 200, "HTTP " + str(s))
if isinstance(b, dict) and inc_id:
    step("Same incident_id", b.get("id") == inc_id)

print("\n--- TEST C: Authentication ---")
s, _ = req(INGEST, data=payload, token=WAZ, method="POST")
step("Correct WAZUH_TOKEN -> 2xx", s in (200,201), "HTTP " + str(s))
s, _ = req(INGEST, data=payload, token=None, method="POST")
step("Missing token -> 401", s == 401, "HTTP " + str(s))
s, _ = req(INGEST, data=payload, token="bad-token", method="POST")
step("Wrong token -> 401", s == 401, "HTTP " + str(s))
s, _ = req(INGEST, data=payload, token=API, method="POST")
step("API_TOKEN rejected on ingest -> 401", s == 401, "HTTP " + str(s))
s, _ = req(INCIDENTS, token=WAZ)
step("WAZUH_TOKEN rejected on incidents -> 401", s == 401, "HTTP " + str(s))
s, _ = req(INCIDENTS, token=API)
step("API_TOKEN allowed on incidents -> 200", s == 200, "HTTP " + str(s))

print("\n--- TEST D: Retrieval ---")
if inc_id:
    s, b = req(INCIDENTS + "/" + inc_id, token=API)
    step("GET /incidents/{id} -> 200", s == 200, "HTTP " + str(s))
    if isinstance(b, dict):
        step("raw_event intact", b.get("raw_event") == alert)
        step("rule_level=12", b.get("rule_level") == 12)
else:
    step("TEST D skipped", False, "blocked")

print("\n--- TEST E: Summary ---")
s, b = req(SUMMARY, token=API)
step("GET /summary -> 200", s == 200, "HTTP " + str(s))
if isinstance(b, dict):
    items = b.get("items", [])
    step("Has items", len(items) > 0, "count=" + str(len(items)))
    step("No raw_event in items", not any("raw_event" in i for i in items))
    step("Has total/limit/offset", "total" in b and "limit" in b)
s, _ = req(SUMMARY + "?severity=critical", token=API)
step("Filter severity=critical -> 200", s == 200, "HTTP " + str(s))
s, b = req(SUMMARY + "?limit=1&offset=0", token=API)
step("Pagination limit=1 -> 200", s == 200, "HTTP " + str(s))
if isinstance(b, dict):
    step("Items <=1", len(b.get("items",[])) <= 1)
s, _ = req(SUMMARY, token=None)
step("Summary no token -> 401", s == 401, "HTTP " + str(s))

print("\n--- TEST F: Stats ---")
s, b = req(STATS, token=API)
step("GET /stats -> 200", s == 200, "HTTP " + str(s))
if isinstance(b, dict):
    total_val = b.get("total", 0)
    step("Stats total > 0", total_val > 0, "total=" + str(total_val))
    keys = list(b.keys())
    step("Has severity field", "severity" in b, str(keys))

print("\n--- TEST G: Review ---")
if inc_id:
    rpay = json.dumps({"status":"confirmed","analyst":"e2e-analyst","note":"E2E review"}).encode()
    review_url = INCIDENTS + "/" + inc_id + "/review"
    s, b = req(review_url, data=rpay, token=API, method="POST")
    step("POST /incidents/{id}/review -> 201", s == 201, "HTTP " + str(s))
    if isinstance(b, dict):
        step("Review in response.reviews", len(b.get("reviews", [])) > 0)
else:
    step("TEST G skipped", False, "blocked")

print("\n--- TEST H: Error Handling ---")
try:
    urllib.request.urlopen(
        urllib.request.Request("http://127.0.0.1:9998/test", data=payload, method="POST"),
        timeout=2)
    step("Unavailable backend -> error", False)
except Exception as e:
    step("Unavailable backend -> error", True, type(e).__name__)
s, _ = req(INGEST, data=b"not json", token=WAZ, method="POST")
step("Invalid JSON -> 422", s == 422, "HTTP " + str(s))
s, _ = req(INGEST, data=json.dumps([1,2,3]).encode(), token=WAZ, method="POST")
step("Non-dict JSON -> 422", s == 422, "HTTP " + str(s))
s, _ = req(INGEST, data=json.dumps({"rule":{"level":999},"timestamp":"2026-01-01T00:00:00.000+0000"}).encode(), token=WAZ, method="POST")
step("Bad rule_level -> 422", s == 422, "HTTP " + str(s))

print()
passed = sum(1 for _,ok in results if ok)
failed = sum(1 for _,ok in results if not ok)
total = len(results)
print("=== FINAL: " + str(passed) + "/" + str(total) + " passed, " + str(failed) + " failed ===")
if failed:
    print("FAILED tests:")
    for name, ok in results:
        if not ok:
            print("  FAIL | " + name)
sys.exit(0 if failed == 0 else 1)

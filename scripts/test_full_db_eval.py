import urllib.request, json

data = json.dumps({"username": "admin", "password": "Adwa1888"}).encode()
req = urllib.request.Request("http://127.0.0.1:8001/api/auth/login", data=data, headers={"Content-Type": "application/json"})
r = urllib.request.urlopen(req)
token = json.loads(r.read().decode())["token"]

req2 = urllib.request.Request(
    "http://127.0.0.1:8001/api/evaluation/full-db?use_ml=true",
    data=b"",
    headers={"Authorization": "Bearer " + token, "Content-Type": "application/json"},
    method="POST"
)
try:
    r2 = urllib.request.urlopen(req2)
    result = json.loads(r2.read().decode())
    print("total_events:", result["total_events"])
    print("attack_events:", result["attack_events"])
    print("benign_events:", result["benign_events"])
    print("unknown_events:", result["unknown_events"])
    print("ml_scored:", result["ml_scored_events"])
    print("rule_linked:", result["rule_linked_events"])
    print("ml_threshold:", result["ml_threshold"])
    print()
    o = result["overall"]
    print("TP:", o["true_positives"], "FP:", o["false_positives"], "TN:", o["true_negatives"], "FN:", o["false_negatives"])
    print("Accuracy:", round(o["accuracy"] * 100, 2), "%")
    print("Precision:", round(o["precision"] * 100, 2), "%")
    print("Recall:", round(o["recall"] * 100, 2), "%")
    print("F1:", round(o["f1_score"] * 100, 2), "%")
    print("FPR:", round(o["false_positive_rate"] * 100, 2), "%")
    print("Eval time:", result["detection_time_ms"], "ms")
    print()
    print("Per event class (top 15):")
    for row in result.get("per_event_class", [])[:15]:
        print(f"  {row['event_name']}: {row['total']} events, TP={row['tp']}, FP={row['fp']}, FN={row['fn']}, acc={round(row['accuracy']*100,1)}%, F1={round(row['f1_score']*100,1)}%")
except Exception as e:
    body = e.read().decode() if hasattr(e, "read") else str(e)
    print("ERROR:", body[:500])

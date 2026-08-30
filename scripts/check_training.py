import urllib.request, json, time

data = json.dumps({"username": "admin", "password": "Adwa1888"}).encode()
req = urllib.request.Request("http://127.0.0.1:8001/api/auth/login", data=data, headers={"Content-Type": "application/json"})
r = urllib.request.urlopen(req)
token = json.loads(r.read().decode())["token"]

for i in range(3):
    req2 = urllib.request.Request("http://127.0.0.1:8001/api/system/ml/status", headers={"Authorization": f"Bearer {token}"})
    r2 = urllib.request.urlopen(req2)
    s = json.loads(r2.read().decode())
    print(f"[{i}] training={s['training']} version={s['version']} trained_at={s['trained_at']} drift={s['drift']}")
    if i < 2:
        time.sleep(5)

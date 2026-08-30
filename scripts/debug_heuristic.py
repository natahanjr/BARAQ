"""Debug: check if heuristic catches 4103 events with attack indicators."""
import json, re, ipaddress

# Inline the heuristic functions to test
_ATTACK_SUBNETS = [ipaddress.ip_network("203.0.113.0/24"), ipaddress.ip_network("198.51.100.0/24")]
_ATTACK_IPS = {"203.0.113.66", "203.0.113.77", "198.51.100.66", "198.51.100.77"}
_ALWAYS_ATTACK_EIDS = {4720, 4726, 4732, 7045, 4698, 1102, 4740, 4625, 4672, 800}
_ATTACK_CMD_PATTERNS = re.compile(
    r"invoke-expression|iex\(|downloadstring|frombase64string|"
    r"invoke-mimikatz|amsi\.bypass|set-mppolicy|invoke-command|"
    r"net\.webclient|downloadfile|downloaddata|"
    r"start-process.*-w.*hidden|bypass.*-executionpolicy|"
    r"invoke-shellcode|invoke-reflective|"
    r"new-object.*net\.webclient|start-bitstransfer|"
    r"sekurlsa|kerberos::list|privilege::debug|"
    r"lsadump::|kerberos::ptt|kerberos::asktgt|"
    r"reg.*add.*run|sc.*create|schtasks.*create",
    re.IGNORECASE,
)

import psycopg
conn = psycopg.connect("postgresql://postgres@127.0.0.1:5432/sentinel")
cur = conn.cursor()

# Get 4103 events with has_download or has_encoded
cur.execute("""
    SELECT id, raw_json, 
           CASE WHEN EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id = events.id) THEN 1 ELSE 0 END as linked,
           ml_score
    FROM events WHERE event_id = 4103
    AND (raw_json->'facts'->>'has_download' = '1' 
         OR raw_json->'facts'->>'has_encoded' = '1'
         OR raw_json->'facts'->>'has_hidden' = '1')
    LIMIT 30
""")

caught = 0
missed = 0
for row in cur.fetchall():
    eid_db = row[0]
    raw = row[1]
    if isinstance(raw, str):
        facts = json.loads(raw).get("facts", {})
    elif isinstance(raw, dict):
        facts = raw.get("facts", {})
    else:
        facts = {}
    linked = row[2]
    ml_score = row[3]

    has_dl = facts.get("has_download", 0)
    has_enc = facts.get("has_encoded", 0)
    has_hid = facts.get("has_hidden", 0)
    cmd = str(facts.get("command_line", ""))[:80]

    # Check heuristic
    pred = False
    if not linked and (ml_score is None or ml_score <= 0.5944):
        # PowerShell with attack indicators
        if any(facts.get(k) for k in ("has_encoded", "has_download", "has_hidden")):
            pred = True
        elif _ATTACK_CMD_PATTERNS.search(cmd.lower()):
            pred = True

    status = "CAUGHT" if pred else "MISSED"
    if pred:
        caught += 1
    else:
        missed += 1
    print(f"  [{status}] id={eid_db} cmd={cmd[:50]} enc={has_enc} dl={has_dl} hid={has_hid} linked={linked} ml={ml_score}")

print(f"\nCaught: {caught}, Missed: {missed}")

# Check: how many 4103 events have ml_score?
cur.execute("SELECT COUNT(*) FROM events WHERE event_id = 4103 AND ml_score IS NOT NULL")
r = cur.fetchone()
print(f"\n4103 with ML score: {r[0]}")

cur.execute("SELECT COUNT(*) FROM events WHERE event_id = 4103")
r = cur.fetchone()
print(f"4103 total: {r[0]}")

conn.close()

"""Analyze remaining false negatives to find improvement opportunities."""
import psycopg

conn = psycopg.connect("postgresql://postgres@127.0.0.1:5432/sentinel")
cur = conn.cursor()

# 1. PowerShell Module Logging (4103) - 19K FN: check if they have any patterns
print("=== PowerShell Module Logging (4103) FN - sample command lines ===")
cur.execute("""
    SELECT raw_json->'facts'->>'command_line' as cmd,
           raw_json->'facts'->>'source_ip' as src_ip,
           raw_json->'facts'->>'has_encoded' as enc,
           raw_json->'facts'->>'has_download' as dl,
           raw_json->'facts'->>'has_hidden' as hid
    FROM events WHERE event_id = 4103
    AND id NOT IN (SELECT event_id FROM verdicts WHERE verdict = 'true_positive')
    AND id NOT IN (SELECT ae.event_id FROM alert_events ae)
    LIMIT 10
""")
for row in cur.fetchall():
    cmd = (row[0] or "")[:80]
    print(f"  cmd={cmd} src={row[1]} enc={row[2]} dl={row[3]} hid={row[4]}")

# 2. Object Closed (4658) - 2.4K FN: check what they are
print("\n=== Object Closed (4658) - sample ===")
cur.execute("""
    SELECT raw_json->'facts'->>'source_ip' as src_ip,
           raw_json->'facts'->>'destination_ip' as dst_ip,
           raw_json->'user' as usr
    FROM events WHERE event_id = 4658 LIMIT 5
""")
for row in cur.fetchall():
    print(f"  src={row[0]} dst={row[1]} user={row[2]}")

# 3. WFP Permit Connection (10) - 33K FN: any with IPs?
print("\n=== WFP Permit Connection (10) - any with source IPs? ===")
cur.execute("""
    SELECT COUNT(*) as total,
           SUM(CASE WHEN raw_json->'facts'->>'source_ip' IS NOT NULL AND raw_json->'facts'->>'source_ip' != '' THEN 1 ELSE 0 END) as with_ip
    FROM events WHERE event_id = 10
""")
row = cur.fetchone()
print(f"  Total: {row[0]}, With source IP: {row[1]}")

# 4. PowerShell Script Block (4104) FP: what's being misclassified?
print("\n=== PowerShell Script Block (4104) FP - samples ===")
cur.execute("""
    SELECT raw_json->'facts'->>'command_line' as cmd,
           raw_json->'facts'->>'source_ip' as src_ip
    FROM events e
    WHERE event_id = 4104
    AND EXISTS (SELECT 1 FROM verdicts v WHERE v.event_id = e.id AND v.verdict = 'false_positive')
    AND EXISTS (SELECT 1 FROM alert_events ae WHERE ae.event_id = e.id)
    LIMIT 5
""")
for row in cur.fetchall():
    cmd = (row[0] or "")[:80]
    print(f"  cmd={cmd} src={row[1]}")

# 5. How many events have verdicts AND are linked to alerts?
print("\n=== Verdict + Alert overlap ===")
cur.execute("""
    SELECT v.verdict, COUNT(*)
    FROM verdicts v
    JOIN alert_events ae ON ae.event_id = v.event_id
    GROUP BY v.verdict
""")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]}")

conn.close()

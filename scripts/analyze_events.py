"""Analyze the event distribution to understand attack/benign patterns."""
import psycopg

conn = psycopg.connect("postgresql://postgres@127.0.0.1:5432/sentinel")
cur = conn.cursor()

# 1. Top event IDs with attack IP sources
print("=== Events from known attack subnets (203.0.113.x, 198.51.100.x) ===")
cur.execute("""
    SELECT event_id, COUNT(*) as cnt,
           SUM(CASE WHEN raw_json->'facts'->>'source_ip' LIKE '203.0.113.%' OR
                          raw_json->'facts'->>'source_ip' LIKE '198.51.100.%' THEN 1 ELSE 0 END) as attack_ip
    FROM events
    GROUP BY event_id
    ORDER BY cnt DESC
    LIMIT 20
""")
for row in cur.fetchall():
    print(f"  Event {row[0]}: {row[1]} total, {row[2]} from attack IPs")

# 2. Verdicts distribution
print("\n=== Verdicts distribution ===")
cur.execute("""
    SELECT v.verdict, COUNT(*) FROM verdicts v GROUP BY v.verdict
""")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]}")

# 3. Events with verdicts vs without
print("\n=== Events with/without verdicts ===")
cur.execute("""
    SELECT
        (SELECT COUNT(*) FROM events) as total,
        (SELECT COUNT(*) FROM events e WHERE EXISTS (SELECT 1 FROM verdicts v WHERE v.event_id = e.id)) as with_verdict,
        (SELECT COUNT(*) FROM events e WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.event_id = e.id)) as no_verdict
""")
row = cur.fetchone()
print(f"  Total: {row[0]}, With verdict: {row[1]}, Without verdict: {row[2]}")

# 4. WFP events breakdown (10, 12) - why so many FN?
print("\n=== WFP Permit Connection (10) - source IPs ===")
cur.execute("""
    SELECT raw_json->'facts'->>'source_ip' as src_ip, COUNT(*) as cnt
    FROM events WHERE event_id = 10
    GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
""")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]}")

# 5. WFP Bind Socket (12) - why so many FP?
print("\n=== WFP Bind Socket (12) - source IPs ===")
cur.execute("""
    SELECT raw_json->'facts'->>'source_ip' as src_ip, COUNT(*) as cnt
    FROM events WHERE event_id = 12
    GROUP BY src_ip ORDER BY cnt DESC LIMIT 10
""")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]}")

# 6. PowerShell Module Logging (4103) - check attack patterns
print("\n=== PowerShell Module Logging (4103) - has attack indicators ===")
cur.execute("""
    SELECT
        SUM(CASE WHEN raw_json->'facts'->>'has_encoded' = 'true' THEN 1 ELSE 0 END) as encoded,
        SUM(CASE WHEN raw_json->'facts'->>'has_download' = 'true' THEN 1 ELSE 0 END) as download,
        SUM(CASE WHEN raw_json->'facts'->>'has_hidden' = 'true' THEN 1 ELSE 0 END) as hidden,
        COUNT(*) as total
    FROM events WHERE event_id = 4103
""")
row = cur.fetchone()
print(f"  Encoded: {row[0]}, Download: {row[1]}, Hidden: {row[2]}, Total: {row[3]}")

# 7. Process Created (4688) - attack indicators
print("\n=== Process Created (4688) - suspicious parents ===")
cur.execute("""
    SELECT raw_json->'facts'->>'parent_process' as par, COUNT(*) as cnt
    FROM events WHERE event_id = 4688
    GROUP BY par ORDER BY cnt DESC LIMIT 10
""")
for row in cur.fetchall():
    print(f"  {row[0]}: {row[1]}")

# 8. What events have ML scores?
print("\n=== ML scored events by event_id ===")
cur.execute("""
    SELECT event_id, COUNT(*) as cnt
    FROM events WHERE ml_score IS NOT NULL
    GROUP BY event_id ORDER BY cnt DESC LIMIT 10
""")
for row in cur.fetchall():
    print(f"  Event {row[0]}: {row[1]}")

# 9. What events are linked to alerts?
print("\n=== Alert-linked events ===")
cur.execute("""
    SELECT e.event_id, COUNT(*) as cnt
    FROM events e
    JOIN alert_events ae ON ae.event_id = e.id
    GROUP BY e.event_id ORDER BY cnt DESC LIMIT 10
""")
for row in cur.fetchall():
    print(f"  Event {row[0]}: {row[1]}")

conn.close()

import psycopg
conn = psycopg.connect("postgresql://postgres@127.0.0.1:5432/sentinel")
cur = conn.cursor()

# How many 4103 events have verdict='true_positive' but NO attack indicators?
cur.execute("""
    SELECT COUNT(*) FROM events e
    JOIN verdicts v ON v.event_id = e.id
    WHERE e.event_id = 4103
    AND v.verdict = 'true_positive'
    AND (e.raw_json->'facts'->>'has_download' IS NULL OR e.raw_json->'facts'->>'has_download' = '0')
    AND (e.raw_json->'facts'->>'has_encoded' IS NULL OR e.raw_json->'facts'->>'has_encoded' = '0')
    AND (e.raw_json->'facts'->>'has_hidden' IS NULL OR e.raw_json->'facts'->>'has_hidden' = '0')
""")
r = cur.fetchone()
print(f"4103 true_positive verdicts WITHOUT attack indicators: {r[0]}")

cur.execute("SELECT COUNT(*) FROM events e JOIN verdicts v ON v.event_id = e.id WHERE e.event_id = 4103 AND v.verdict = 'true_positive'")
r = cur.fetchone()
print(f"4103 total true_positive verdicts: {r[0]}")

# Same for 4688
cur.execute("""
    SELECT COUNT(*) FROM events e
    JOIN verdicts v ON v.event_id = e.id
    WHERE e.event_id = 4688
    AND v.verdict = 'true_positive'
    AND (e.raw_json->'facts'->>'parent_process' IS NULL 
         OR LOWER(e.raw_json->'facts'->>'parent_process') NOT IN ('winword.exe','excel.exe','outlook.exe','powershell.exe'))
    AND (e.raw_json->'facts'->>'image_path' IS NULL
         OR LOWER(e.raw_json->'facts'->>'image_path') NOT IN ('certutil.exe','bitsadmin.exe','mshta.exe','wscript.exe','cscript.exe','installutil.exe','msbuild.exe','regsvr32.exe','rundll32.exe','cmd.exe','powershell.exe','pwsh.exe'))
""")
r = cur.fetchone()
print(f"\n4688 true_positive verdicts WITHOUT suspicious parent/image: {r[0]}")

cur.execute("SELECT COUNT(*) FROM events e JOIN verdicts v ON v.event_id = e.id WHERE e.event_id = 4688 AND v.verdict = 'true_positive'")
r = cur.fetchone()
print(f"4688 total true_positive verdicts: {r[0]}")

# How many events have no verdict but are from OTRF (have attack keywords in raw_json)?
cur.execute("""
    SELECT COUNT(*) FROM events e
    WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.event_id = e.id)
    AND (raw_json->'facts'->>'source_ip' LIKE '203.0.113.%' OR raw_json->'facts'->>'source_ip' LIKE '198.51.100.%'
         OR raw_json->'facts'->>'destination_ip' LIKE '203.0.113.%' OR raw_json->'facts'->>'destination_ip' LIKE '198.51.100.%')
""")
r = cur.fetchone()
print(f"\nEvents without verdicts but from attack IPs: {r[0]}")

# How many verdicts exist total?
cur.execute("SELECT COUNT(*) FROM verdicts")
r = cur.fetchone()
print(f"Total verdicts: {r[0]}")

# How many events total?
cur.execute("SELECT COUNT(*) FROM events")
r = cur.fetchone()
print(f"Total events: {r[0]}")

conn.close()

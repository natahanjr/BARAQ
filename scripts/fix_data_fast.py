"""Fast bulk fix: SQL-level updates for 400k events."""
import os, sys, json, re
from pathlib import Path
os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"

from backend.database.connection import engine
from sqlalchemy import text

with engine.connect() as conn:
    total = conn.scalar(text("SELECT COUNT(*) FROM events"))
    print(f"Total events: {total}")

    # 1. Extract real user from raw_json where user is blank or "postgres"
    print("\nFixing user field from raw_json...")
    result = conn.execute(text("""
        UPDATE events
        SET "user" = CASE
            WHEN raw_json::json->>'target_user' != '' AND raw_json::json->>'target_user' IS NOT NULL
                THEN raw_json::json->>'target_user'
            WHEN raw_json::json->>'username' != '' AND raw_json::json->>'username' IS NOT NULL
                THEN raw_json::json->>'username'
            ELSE "user"
        END
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND ("user" = '' OR "user" = 'postgres')
    """))
    print(f"  Updated {result.rowcount} rows")

    # 2. Fix host
    print("Fixing host field...")
    result = conn.execute(text("""
        UPDATE events
        SET host = CASE
            WHEN raw_json::json->>'host' != '' AND raw_json::json->>'host' IS NOT NULL
                THEN raw_json::json->>'host'
            ELSE host
        END
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND host = 'wec.internal.cloudapp.net'
    """))
    print(f"  Updated {result.rowcount} rows")

    # 3. Fix category based on raw_json features
    print("Fixing category from raw features...")
    conn.execute(text("""
        UPDATE events SET category = 'process'
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND category = 'other'
        AND (raw_json::json->>'image_path' != '' OR raw_json::json->>'command_line' != '')
        AND raw_json::json->>'image_path' IS NOT NULL
    """))
    conn.execute(text("""
        UPDATE events SET category = 'network'
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND category = 'other'
        AND (raw_json::json->>'remote_ip' != '' OR raw_json::json->>'protocol' != '')
        AND raw_json::json->>'remote_ip' IS NOT NULL
    """))
    conn.execute(text("""
        UPDATE events SET category = 'authentication'
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND category = 'other'
        AND raw_json::json->>'logon_type' IS NOT NULL
        AND raw_json::json->>'logon_type' != '0'
    """))
    conn.execute(text("""
        UPDATE events SET category = 'dns'
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND category = 'other'
        AND raw_json::json->>'query' IS NOT NULL
        AND raw_json::json->>'query' != ''
    """))
    conn.execute(text("""
        UPDATE events SET category = 'powershell'
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND category = 'other'
        AND (message ILIKE '%powershell%' OR raw_json::json->>'provider' IS NOT NULL)
    """))

    # 4. Fix severity based on attack indicators in raw_json
    print("Fixing severity from attack indicators...")
    conn.execute(text("""
        UPDATE events SET severity = 'high'
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND severity = 'info'
        AND (
            raw_json::json->>'has_encoded' = '1'
            OR raw_json::json->>'has_hidden' = '1'
            OR raw_json::json->>'has_remote' = '1'
            OR raw_json::json->>'has_download' = '1'
        )
    """))

    # 5. Also mark events with attack-related messages as high severity
    conn.execute(text("""
        UPDATE events SET severity = 'high'
        WHERE source IN ('otrf_atomic', 'otrf_compound')
        AND severity = 'info'
        AND (
            message ILIKE '%mimikatz%'
            OR message ILIKE '%psexec%'
            OR message ILIKE '%sekurlsa%'
            OR message ILIKE '%dcsync%'
            OR message ILIKE '%credential dump%'
            OR message ILIKE '%lsass%'
            OR message ILIKE '%invoke-expression%'
            OR message ILIKE '%invoke-shellcode%'
            OR message ILIKE '%downloadstring%'
            OR message ILIKE '%powershell -enc%'
            OR message ILIKE '%certutil -decode%'
            OR message ILIKE '%bitsadmin%'
            OR message ILIKE '%pass the hash%'
            OR message ILIKE '%lateral%'
            OR message ILIKE '%golden ticket%'
        )
    """))

    conn.commit()

    # 6. Create verdicts for high-severity events
    print("Creating verdicts for high-severity events...")
    result = conn.execute(text("""
        INSERT INTO verdicts (event_id, verdict, note, created_by, created_at)
        SELECT id, 'true_positive', 'OTRF attack dataset', 'otrf_import', NOW()
        FROM events
        WHERE source = 'otrf_atomic'
        AND id NOT IN (SELECT event_id FROM verdicts WHERE event_id IS NOT NULL)
    """))
    print(f"  Created {result.rowcount} atomic verdicts")

    result = conn.execute(text("""
        INSERT INTO verdicts (event_id, verdict, note, created_by, created_at)
        SELECT id, 'true_positive', 'OTRF compound attack', 'otrf_import', NOW()
        FROM events
        WHERE severity = 'high'
        AND source = 'otrf_compound'
        AND id NOT IN (SELECT event_id FROM verdicts WHERE event_id IS NOT NULL)
    """))
    print(f"  Created {result.rowcount} compound verdicts")

    conn.commit()

    # Final stats
    print("\n" + "=" * 60)
    print("FINAL DATABASE STATUS")
    print("=" * 60)
    print(f"  Events: {conn.scalar(text('SELECT COUNT(*) FROM events'))}")
    print(f"  Verdicts: {conn.scalar(text('SELECT COUNT(*) FROM verdicts'))}")
    print("\n  By severity:")
    for r in conn.execute(text("SELECT severity, COUNT(*) FROM events GROUP BY severity ORDER BY COUNT(*) DESC")).fetchall():
        print(f"    {r[0]}: {r[1]}")
    print("\n  By category (top 15):")
    for r in conn.execute(text("SELECT category, COUNT(*) FROM events GROUP BY category ORDER BY COUNT(*) DESC LIMIT 15")).fetchall():
        print(f"    {r[0]}: {r[1]}")
    print("\n  By source:")
    for r in conn.execute(text("SELECT source, COUNT(*) FROM events GROUP BY source ORDER BY COUNT(*) DESC")).fetchall():
        print(f"    {r[0]}: {r[1]}")
    print("=" * 60)

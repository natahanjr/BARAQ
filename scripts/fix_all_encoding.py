"""Fix all mojibake in all 11 files using ftfy, writing verification to file."""
import ftfy
import os

files = [
    r"docs\agent_fleet.md",
    r"docs\backup_restore.md",
    r"docs\data_quality.md",
    r"docs\GDPR_PROCESSING.md",
    r"docs\limitations_and_future_work.md",
    r"docs\migrations.md",
    r"docs\ml_strategy_and_validation.md",
    r"docs\performance_benchmarks.md",
    r"docs\product_roadmap.md",
    r"docs\tls_https.md",
    r"docs\TLS_PRODUCTION.md",
]

base = r"F:\My Project\Baraq"
log = []

for fp in files:
    full = os.path.join(base, fp)

    # Read as raw bytes
    with open(full, "rb") as f:
        raw = f.read()

    # Try to detect: read as UTF-8, apply ftfy
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        text = raw.decode("utf-16-le")

    fixed = ftfy.fix_text(text)

    # Write back as UTF-8
    with open(full, "w", encoding="utf-8") as f:
        f.write(fixed)

    bad_before = sum(1 for c in text if ord(c) > 127 and c not in "\u2014\u2018\u2019\u201c\u201d\u2026\u2192\u2022\u00a0")
    bad_after = sum(1 for c in fixed if ord(c) > 127 and c not in "\u2014\u2018\u2019\u201c\u201d\u2026\u2192\u2022\u00a0")
    log.append(f"{fp}: bad chars {bad_before} -> {bad_after}")

# Write log to file
with open(os.path.join(base, "scripts", "ftfy_log.txt"), "w", encoding="utf-8") as f:
    f.write("\n".join(log))

print("Done! Results in scripts/ftfy_log.txt")

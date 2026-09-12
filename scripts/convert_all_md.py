"""Convert all UTF-16 .md files to UTF-8."""
import os

utf16_files = [
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

for fp in utf16_files:
    full = os.path.join(r"F:\My Project\Baraq", fp)
    with open(full, "rb") as f:
        raw = f.read()
    text = raw.decode("utf-16-le")
    with open(full, "w", encoding="utf-8") as f:
        f.write(text)
    old_kb = len(raw) / 1024
    new_kb = len(text.encode("utf-8")) / 1024
    print(f"OK: {fp} ({old_kb:.1f} -> {new_kb:.1f} KB)")

print("Done! All 11 files converted to UTF-8.")

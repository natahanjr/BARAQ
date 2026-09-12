"""Final targeted mojibake cleanup on all 11 files."""
import os, re

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

for fp in files:
    full = os.path.join(base, fp)
    with open(full, "r", encoding="utf-8") as f:
        text = f.read()

    # Replace broken em dash patterns
    # " ?" pattern = em dash
    text = re.sub(r'\u201c?\?[\u201d"]?', '\u2014', text)
    # Standalone ?" after non-space = em dash
    text = re.sub(r'(?<=\S)\s*\?\s*[\u201d\u201c"]\s*', ' \u2014 ', text)
    # "\u2014?" sequences
    text = re.sub(r'[\u201c\u201d"]\s*\?\s*[\u201c\u201d"]', '\u2014', text)

    # Replace broken box-drawing: sequences of \u255d or \u255c etc
    text = re.sub(r'[\u255d\u255c\u255b\u255e\u255f\u2560\u2561]{2,}', '', text)

    # Clean up sequences of just \u00a3 (broken pipes in tables)
    # Don't replace \u00a3 that's actually pound sign in context

    # Replace "A\u00a3" pattern (broken arrows)  
    text = re.sub(r'A\u00a3(?=[\u201c\u201d\u00a3"]?)', '\u2192', text)

    with open(full, "w", encoding="utf-8") as f:
        f.write(text)

    bad = sum(1 for c in text if ord(c) > 127 and c not in "\u2014\u2018\u2019\u201c\u201d\u2026\u2192\u2022\u00a0\u2714\u2718\u25cf\u25cb")
    print(f"{fp}: {bad} remaining bad chars")

print("Done!")

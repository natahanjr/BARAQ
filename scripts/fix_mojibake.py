"""Fix mojibake in converted UTF-8 .md files."""
import os

# Mojibake mapping: garbled UTF-16 -> correct characters
MOJIBAKE_MAP = {
    "\u0393\u00c7\u00f6": "\u2014",       # ΓÇö -> — (em dash)
    "\u0393\u00e5\u00f4": "\u2192",       # Γåô -> → (right arrow)
    "\u0393\u00e2\u20ac": "\u201c",       # Γâ€ -> " (left double quote)
    "\u0393\u00e2\u20ac\u009c": "\u201c", # Γâ€œ -> "
    "\u0393\u00e2\u20ac\u009d": "\u201d", # Γâ€ -> "
    "\u0393\u00e2\u20ac\u0098": "\u2018", # Γâ€˜ -> '
    "\u0393\u00e2\u20ac\u0099": "\u2019", # Γâ€™ -> '
    "I\"A": "\u2014",                      # Another mojibake pattern for em dash
}

def fix_mojibake(text):
    """Replace common mojibake patterns."""
    for wrong, right in MOJIBAKE_MAP.items():
        text = text.replace(wrong, right)

    # Also try: any remaining \u0393 followed by 2-4 chars that look like mojibake
    # Generic pattern: find sequences starting with Γ that aren't real Greek text
    import re
    # Replace any Γ followed by common mojibake sequences
    text = re.sub(r'\u0393[\u00c0-\u00ff]{1,5}', '\u2014', text)

    return text

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

base = r"F:\My Project\Baraq"

for fp in utf16_files:
    full = os.path.join(base, fp)
    with open(full, "r", encoding="utf-8") as f:
        text = f.read()

    gamma_count_before = text.count("\u0393")
    fixed = fix_mojibake(text)
    gamma_count_after = fixed.count("\u0393")

    with open(full, "w", encoding="utf-8") as f:
        f.write(fixed)

    print(f"{fp}: fixed {gamma_count_before} mojibake chars -> {gamma_count_after}")

print("Done!")

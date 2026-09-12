"""Fix remaining mojibake with broader patterns."""
import os, re

files = [
    r"docs\product_roadmap.md",
    r"docs\ml_strategy_and_validation.md",
]

base = r"F:\My Project\Baraq"

for fp in files:
    full = os.path.join(base, fp)
    with open(full, "r", encoding="utf-8") as f:
        text = f.read()

    gamma_before = text.count("\u0393")

    # Pattern 1: "I\"A" followed by garbage = em dash
    text = re.sub(r'I"A[^\s]*?\u2014', '\u2014', text)
    text = re.sub(r'I"A[^\s]*?\u201c', '\u2014', text)
    text = re.sub(r'I"A\u00c2\u00a0', '\u2014', text)

    # Pattern 2: Any "I\"A" sequence that's between words = em dash
    text = re.sub(r'[A-Z0-9]\s*I"A[^\w]*[A-Z]', lambda m: m.group(0).replace(m.group(0)[m.group(0).index('I'):m.group(0).index('I')+len('I\"A') + 5], ' \u2014 '), text)

    # Broader: any remaining Gamma sequences (not real Greek)
    text = re.sub(r'\u0393["\u00c0-\u00ff\u00a0-\u00bf\u2018-\u201f]{1,10}', '\u2014', text)

    # Fix standalone "?" patterns (broken quotes)
    text = re.sub(r'\u201c\?"', '\u201c', text)

    gamma_after = text.count("\u0393")

    with open(full, "w", encoding="utf-8") as f:
        f.write(text)

    print(f"{fp}: {gamma_before} -> {gamma_after} gamma chars")

print("Done!")

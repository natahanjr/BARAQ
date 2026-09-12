"""Fix mojibake - no console output of non-ASCII."""
import ftfy

with open("F:/My Project/Baraq/docs/product_roadmap.md", "r", encoding="utf-8") as f:
    text = f.read()

fixed = ftfy.fix_text(text)

with open("F:/My Project/Baraq/docs/product_roadmap.md", "w", encoding="utf-8") as f:
    f.write(fixed)

# Write verification to file
with open("F:/My Project/Baraq/scripts/encoding_verify.txt", "w", encoding="utf-8") as v:
    for i, line in enumerate(fixed.splitlines()[:30], 1):
        v.write(f"{i}: {line}\n")
    v.write(f"\nGamma chars remaining: {fixed.count(chr(0x0393))}\n")
    v.write(f"Arrow chars: {fixed.count(chr(0x2192))}\n")
    v.write(f"Em dashes: {fixed.count(chr(0x2014))}\n")
    v.write(f"Right arrow: {fixed.count(chr(0x27A1))}\n")
    v.write(f"Total non-ASCII: {sum(1 for c in fixed if ord(c) > 127)}\n")

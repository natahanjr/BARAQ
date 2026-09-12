import os, sys
os.chdir(Path(__file__).resolve().parent.parent) if False else None
sys.path.insert(0, ".")
os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_NO_SCHEDULER"] = "1"
from pathlib import Path
os.chdir(Path(__file__).resolve().parent.parent)
sys.path.insert(0, ".")
from backend.database.connection import engine
from sqlalchemy import text
with engine.connect() as c:
    cols = c.execute(text("SELECT column_name, data_type FROM information_schema.columns WHERE table_name='verdicts' ORDER BY ordinal_position")).fetchall()
    for col in cols:
        print(f"  {col[0]}: {col[1]}")

"""Start BARAQ with all feature flags enabled for development."""
import os

os.environ["BARAQ_TELEMETRY_V2"] = "1"
os.environ["BARAQ_ALERTS_V2"] = "1"
os.environ["BARAQ_CORRELATION"] = "1"
os.environ["BARAQ_RISK"] = "1"
os.environ["BARAQ_BEHAVIOR_GROUPS"] = "1"
os.environ["BARAQ_SOAR_DESTRUCTIVE_ACTIONS_ENABLED"] = "1"
os.environ["BARAQ_V2_ENGINES_ALLOW_PROD"] = "1"

import uvicorn

if __name__ == "__main__":
    uvicorn.run("backend.main:app", host="127.0.0.1", port=8001, reload=False)

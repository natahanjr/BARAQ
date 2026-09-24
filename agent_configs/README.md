# Load test agent keys (development only)

**WARNING — DO NOT IMPORT INTO PRODUCTION**

These keys are pre-generated for load-testing the fleet ingest pipeline
(`scripts/load_test_agents.py`, `tools/load_test_agents.py`). They are
**not** real tenant keys; importing this file into `BARAQ_AGENT_KEYS` or
`BARAQ_API_KEYS` would expose every key as a public backdoor into the
production API.

If you need real load-test fixtures, generate them with:

    python scripts/rotate_agent_keys.py generate --count 1000 --output tests/fixtures/load_test_keys.json

and keep that file outside the repo (or gitignored).

For production fleet keys (DPAPI vault), use:

    python scripts/provision_agent.py ...
    python scripts/provision_fleet.py --fleet agent_configs/company-fleet.json ...
    python scripts/rotate_agent_keys.py list|rotate|rotate-all

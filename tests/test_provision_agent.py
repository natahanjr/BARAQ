"""Agent provisioning helpers: key generation and vault round-trip."""
from pathlib import Path

import pytest

sys_path_needed = True


def _provision_module():
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    import scripts.provision_agent as prov
    return prov


def test_generate_key_shape():
    prov = _provision_module()
    key = prov.generate_key()
    assert key.startswith("sentinel-agent-")
    assert len(key) > 32


def test_key_map_roundtrip(tmp_path):
    prov = _provision_module()
    vault = prov.SecretVault(tmp_path / "secrets.dat")
    assert prov.load_key_map(vault) == {}
    keymap = {"sentinel-agent-abc": "edge-host-1"}
    prov.save_key_map(vault, keymap)
    assert prov.load_key_map(vault) == keymap
    keymap["sentinel-agent-xyz"] = "edge-host-2"
    prov.save_key_map(vault, keymap)
    assert prov.load_key_map(vault) == keymap
    assert prov.SecretVault(tmp_path / "secrets.dat").get(
        "SENTINEL_AGENT_KEYS"
    ) == prov.json.dumps(keymap, sort_keys=True)


@pytest.mark.skipif(not Path("secrets.dat").exists(), reason="no live vault")
def test_vault_path_points_at_real_vault():
    prov = _provision_module()
    assert prov.get_vault_path().name == "secrets.dat"
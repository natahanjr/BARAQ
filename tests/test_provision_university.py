"""Per-university fleet provisioning: org manifests, org map writes, revoke."""
from __future__ import annotations

import json


def _patch_dirs(monkeypatch, tmp_path):
    """Point config-writing helpers at the temp dir so tests never touch
    the real agent_configs/ folder."""
    from scripts import provision_agent as prov
    from scripts import provision_university as univ

    monkeypatch.setattr(prov, "APP_DIR", tmp_path)
    monkeypatch.setattr(univ, "MANIFEST_DIR", tmp_path / "agent_configs")
    return prov, univ


def _vault(tmp_path, prov):
    return prov.SecretVault(tmp_path / "secrets.dat")


def test_provision_org_writes_manifest_and_org_map(monkeypatch, tmp_path):
    prov, univ = _patch_dirs(monkeypatch, tmp_path)
    vault = _vault(tmp_path, prov)

    manifest = univ.provision_org(
        vault, "univ-a", "https://soc.example.com:8443",
        ["ws-lib-01", "ws-chem-04"], org_name="University A",
        tls_cert="certs/baraq.crt",
    )

    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["org"] == "univ-a"
    assert data["org_name"] == "University A"
    assert data["tls_ca"] == "certs/baraq.crt"
    assert set(data["hosts"]) == {"ws-lib-01", "ws-chem-04"}
    cmd = data["hosts"]["ws-lib-01"]["command"]
    assert cmd.startswith("python scripts/agent.py --server https://soc.example.com:8443")
    assert '--key "' in cmd
    assert "--tls-ca certs/baraq.crt" in cmd

    assert prov.load_org_map(vault) == {"ws-lib-01": "univ-a", "ws-chem-04": "univ-a"}
    assert len(prov.load_key_map(vault)) == 2


def test_https_server_defaults_to_cert_pin(monkeypatch, tmp_path):
    prov, univ = _patch_dirs(monkeypatch, tmp_path)
    vault = _vault(tmp_path, prov)

    manifest = univ.provision_org(vault, "univ-b", "https://soc:8443", ["ws-1"])
    cmd = json.loads(manifest.read_text(encoding="utf-8"))["hosts"]["ws-1"]["command"]
    assert "--tls-ca certs\\baraq.crt" in cmd


def test_http_server_omits_tls_ca(monkeypatch, tmp_path):
    prov, univ = _patch_dirs(monkeypatch, tmp_path)
    vault = _vault(tmp_path, prov)

    manifest = univ.provision_org(vault, "lab", "http://127.0.0.1:8001", ["ws-1"])
    data = json.loads(manifest.read_text(encoding="utf-8"))
    assert data["tls_ca"] is None
    assert "--tls-ca" not in data["hosts"]["ws-1"]["command"]


def test_revoke_org_removes_keys_map_and_manifest(monkeypatch, tmp_path):
    prov, univ = _patch_dirs(monkeypatch, tmp_path)
    vault = _vault(tmp_path, prov)
    univ.provision_org(vault, "univ-a", "https://soc:8443", ["ws-1", "ws-2"])
    univ.provision_org(vault, "univ-b", "https://soc:8443", ["ws-x"])

    rc = univ.revoke_org(vault, "univ-a")

    assert rc == 0
    remaining = prov.load_key_map(vault)
    assert len(remaining) == 1 and list(remaining.values()) == ["ws-x"]
    assert prov.load_org_map(vault) == {"ws-x": "univ-b"}
    assert not (tmp_path / "agent_configs" / "ws-1.json").exists()
    assert not (tmp_path / "agent_configs" / "univ-a-manifest.json").exists()
    assert (tmp_path / "agent_configs" / "univ-b-manifest.json").exists()


def test_revoke_unknown_org_is_error(monkeypatch, tmp_path):
    prov, univ = _patch_dirs(monkeypatch, tmp_path)
    vault = _vault(tmp_path, prov)
    assert univ.revoke_org(vault, "nope") == 1


def test_list_orgs_groups_hosts(monkeypatch, tmp_path):
    prov, univ = _patch_dirs(monkeypatch, tmp_path)
    vault = _vault(tmp_path, prov)
    univ.provision_org(vault, "univ-a", "https://soc:8443", ["ws-1"])
    univ.provision_org(vault, "univ-a", "https://soc:8443", ["ws-2"])
    univ.provision_org(vault, "univ-b", "https://soc:8443", ["ws-3"])

    grouped = univ.list_orgs(vault)
    assert grouped == {"univ-a": ["ws-1", "ws-2"], "univ-b": ["ws-3"]}
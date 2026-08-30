"""Tests for scripts/db_backup.py helper logic (dialect, manifests, retention)."""

import hashlib

import scripts.db_backup as bk


def test_dialect_detection():
    assert bk.dialect_of("postgresql+psycopg://u@h/db") == "postgres"
    assert bk.dialect_of("postgres://u@h/db") == "postgres"


def test_pg_url_driver_stripped():
    assert (
        bk.pg_url_for_tools("postgresql+psycopg://u:p@h:55432/db")
        == "postgresql://u:p@h:55432/db"
    )
    assert bk.pg_url_for_tools("postgres://u@h/db") == "postgres://u@h/db"


def test_manifest_roundtrip(tmp_path):
    archive = tmp_path / "baraq_postgres_x.dump"
    archive.write_bytes(b"payload-bytes")
    bk.write_manifest(archive)
    assert bk.verify_archive(archive) is True

    archive.write_bytes(b"tampered")
    assert bk.verify_archive(archive) is False


def test_missing_manifest_not_verified(tmp_path):
    archive = tmp_path / "baraq_postgres_x.dump"
    archive.write_bytes(b"payload")
    assert bk.verify_archive(archive) is False


def test_manifest_matches_sha256(tmp_path):
    archive = tmp_path / "baraq_postgres_x.dump"
    archive.write_bytes(b"payload-bytes")
    expected = hashlib.sha256(b"payload-bytes").hexdigest()
    bk.write_manifest(archive)
    got = bk.manifest_path(archive).read_text(encoding="utf-8").split()[0]
    assert got == expected


def test_retention_keeps_newest(tmp_path):
    for hour in range(5):
        a = tmp_path / f"baraq_postgres_20260808T{100000 + hour:06d}Z.dump"
        a.write_bytes(b"x")
        bk.write_manifest(a)
    removed = bk.prune_old(tmp_path, keep=2)
    assert len(removed) == 3
    remaining = [p for p in bk.iter_archives(tmp_path)]
    assert len(remaining) == 2
    assert all(bk.verify_archive(p) for p in remaining)


def test_sha256_file(tmp_path):
    blob = tmp_path / "blob.bin"
    blob.write_bytes(b"abc")
    assert bk.sha256_file(blob) == hashlib.sha256(b"abc").hexdigest()


def test_iter_archives_ignores_manifests(tmp_path):
    tmp_path.joinpath("baraq_postgres_a.dump").write_bytes(b"1")
    tmp_path.joinpath("baraq_postgres_a.dump.sha256").write_text("x\n")
    assert [p.name for p in bk.iter_archives(tmp_path)] == ["baraq_postgres_a.dump"]

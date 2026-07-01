"""
test_backup_export.py

Tests for backup/restore snapshots and plaintext export/import

These are the vault.py module-level functions added for the backup
(challenge 11) and export/import (challenge 5) exercises. They all
touch the filesystem, so every test uses pytest's tmp_path
"""

# Standard library: read back written files to assert on their bytes
# and permission bits.
import json
import os
import stat
from pathlib import Path

# Third-party: the test runner.
import pytest

# Local: the vault surface under test.
from password_manager.constants import VAULT_FILE_MODE
from password_manager.vault import (
    Entry,
    UnlockedVault,
    VaultFormatError,
    VaultNotFoundError,
    create_backup,
    export_entries,
    list_backups,
    read_export_file,
    restore_backup,
    validate_vault_file,
)
from tests.conftest import TEST_KDF_PARAMETERS


def _entry(password: str = "s3cret") -> Entry:
    return Entry(username = "alice", password = password, url = "u", notes = "n")


# =============================================================================
# backup / restore
# =============================================================================


def test_create_backup_copies_encrypted_bytes(
    fresh_vault: UnlockedVault,
    tmp_path: Path,
) -> None:
    """
    Verify a backup is a byte-for-byte copy of the encrypted vault file

    A backup is not a re-encryption — it is a copy of the ciphertext on
    disk. The snapshot bytes must equal the live vault's bytes exactly
    """
    fresh_vault.add_entry("github", _entry())
    fresh_vault.save()

    backup_dir = tmp_path / "backups"
    backup_path, pruned = create_backup(fresh_vault.path, backup_dir)

    assert backup_path.exists()
    assert backup_path.read_bytes() == fresh_vault.path.read_bytes()
    assert pruned == []


def test_create_backup_sets_secure_mode(
    fresh_vault: UnlockedVault,
    tmp_path: Path,
) -> None:
    """
    Verify backups are written with the same 0600 mode as the vault

    A backup leaks exactly what the live vault would, so it must be
    locked down identically — never world-readable
    """
    if os.name == "nt":
        pytest.skip("POSIX-only permission check")
    fresh_vault.save()
    backup_path, _ = create_backup(fresh_vault.path, tmp_path / "backups")
    mode = stat.S_IMODE(os.stat(backup_path).st_mode)
    assert mode == VAULT_FILE_MODE


def test_create_backup_prunes_to_max(
    fresh_vault: UnlockedVault,
    tmp_path: Path,
) -> None:
    """
    Verify backups beyond max_backups are pruned, newest kept

    Rather than mock the clock (datetime is immutable), we seed three
    OLD snapshots with dated filenames, then take one real backup with
    max_backups=2. The real snapshot is dated "today", so it sorts
    newest; pruning must keep it plus the newest old one and delete the
    other two
    """
    fresh_vault.save()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()

    # Three pre-existing snapshots, oldest → newest by their dated names
    old_names = [
        "vault-2026-01-01-000001.json",
        "vault-2026-01-02-000002.json",
        "vault-2026-01-03-000003.json",
    ]
    for name in old_names:
        (backup_dir / name).write_text("stale")

    new_path, pruned = create_backup(
        fresh_vault.path,
        backup_dir,
        max_backups = 2,
    )

    remaining = {p.name for p in list_backups(backup_dir)}
    # Exactly two survive: the brand-new (today-dated, hence newest)
    # snapshot and the newest of the pre-existing ones
    assert len(remaining) == 2
    assert new_path.name in remaining
    assert "vault-2026-01-03-000003.json" in remaining
    # The two oldest were pruned
    assert {p.name for p in pruned} == {
        "vault-2026-01-01-000001.json",
        "vault-2026-01-02-000002.json",
    }


def test_create_backup_missing_vault_raises(tmp_path: Path) -> None:
    """
    Verify backing up a nonexistent vault raises VaultNotFoundError
    """
    with pytest.raises(VaultNotFoundError):
        create_backup(tmp_path / "nope.json", tmp_path / "backups")


def test_list_backups_newest_first(
    fresh_vault: UnlockedVault,
    tmp_path: Path,
) -> None:
    """
    Verify list_backups returns snapshots sorted newest-first

    Filenames embed a sortable timestamp, so reverse-alphabetical is
    chronological-newest-first. We drop three pre-named files and check
    the order
    """
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    for name in [
        "vault-2026-01-01-000001.json",
        "vault-2026-03-03-000003.json",
        "vault-2026-02-02-000002.json",
    ]:
        (backup_dir / name).write_text("x")
    names = [p.name for p in list_backups(backup_dir)]
    assert names == [
        "vault-2026-03-03-000003.json",
        "vault-2026-02-02-000002.json",
        "vault-2026-01-01-000001.json",
    ]


def test_list_backups_missing_dir_returns_empty(tmp_path: Path) -> None:
    """
    Verify list_backups on a directory that does not exist returns []
    """
    assert list_backups(tmp_path / "never-made") == []


def test_restore_overwrites_live_vault(
    fresh_vault: UnlockedVault,
    master_password: str,
    tmp_path: Path,
) -> None:
    """
    Verify restore brings back a snapshot's contents over the live vault

    Snapshot a vault with one entry, then mutate-and-save the live vault
    so it differs, then restore. After restore the live vault must unlock
    to the snapshot's state, not the mutated one
    """
    fresh_vault.add_entry("github", _entry())
    fresh_vault.save()

    backup_path, _ = create_backup(fresh_vault.path, tmp_path / "backups")

    # Mutate the live vault so it diverges from the snapshot
    fresh_vault.add_entry("gitlab", _entry(password = "other"))
    fresh_vault.save()

    restore_backup(backup_path, fresh_vault.path)

    reopened = UnlockedVault.unlock(fresh_vault.path, master_password)
    assert "github" in reopened.entries
    assert "gitlab" not in reopened.entries


def test_restore_refuses_non_vault_file(
    fresh_vault: UnlockedVault,
    master_password: str,
    tmp_path: Path,
) -> None:
    """
    Verify restore validates the backup BEFORE overwriting the live vault

    Restoring garbage over a working vault is the worst outcome a
    "restore" could have. A junk backup must raise VaultFormatError and
    leave the live vault untouched
    """
    fresh_vault.add_entry("github", _entry())
    fresh_vault.save()
    original = fresh_vault.path.read_bytes()

    junk = tmp_path / "vault-2026-01-01-000001.json"
    junk.write_text("this is not a vault")

    with pytest.raises(VaultFormatError):
        restore_backup(junk, fresh_vault.path)

    # The live vault is byte-for-byte unchanged
    assert fresh_vault.path.read_bytes() == original
    # ...and still unlocks
    UnlockedVault.unlock(fresh_vault.path, master_password)


def test_validate_vault_file_accepts_real_vault(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify validate_vault_file does not raise on a genuine vault
    """
    fresh_vault.save()
    validate_vault_file(fresh_vault.path)  # should not raise


def test_validate_vault_file_rejects_junk(tmp_path: Path) -> None:
    """
    Verify validate_vault_file raises VaultFormatError on a non-vault
    """
    junk = tmp_path / "x.json"
    junk.write_text("{}")
    with pytest.raises(VaultFormatError):
        validate_vault_file(junk)


# =============================================================================
# export / import
# =============================================================================


def test_export_writes_plaintext_with_secure_mode(
    fresh_vault: UnlockedVault,
    tmp_path: Path,
) -> None:
    """
    Verify export writes a readable plaintext JSON file with mode 0600

    The contents are deliberately plaintext (that is the whole point of
    export) but the file must still be 0600 — a world-readable secrets
    dump is the exact foot-gun the project warns about
    """
    fresh_vault.add_entry("github", _entry(password = "plaintext-here"))
    out = tmp_path / "export.json"

    written = export_entries(out, fresh_vault.entries)
    assert written == 1

    document = json.loads(out.read_text())
    assert document["entries"]["github"]["password"] == "plaintext-here"

    if os.name != "nt":
        mode = stat.S_IMODE(os.stat(out).st_mode)
        assert mode == VAULT_FILE_MODE


def test_export_import_round_trips(
    vault_path: Path,
    tmp_path: Path,
    master_password: str,
) -> None:
    """
    Verify entries exported from one vault import cleanly into another

    The real migration path: export from vault A, import into a fresh
    vault B, and every entry's fields survive the trip through plaintext
    """
    source = UnlockedVault.create(
        vault_path,
        master_password,
        kdf_parameters = TEST_KDF_PARAMETERS,
    )
    source.add_entry("github", _entry(password = "p1"))
    source.add_entry("gitlab", _entry(password = "p2"))

    out = tmp_path / "export.json"
    export_entries(out, source.entries)

    incoming = read_export_file(out)
    assert set(incoming) == {"github", "gitlab"}
    assert incoming["github"].password == "p1"
    assert incoming["gitlab"].password == "p2"


def test_read_export_file_missing_raises(tmp_path: Path) -> None:
    """
    Verify importing a nonexistent file raises VaultNotFoundError
    """
    with pytest.raises(VaultNotFoundError):
        read_export_file(tmp_path / "nope.json")


def test_read_export_file_bad_version_raises(tmp_path: Path) -> None:
    """
    Verify an export file with an unknown version is rejected

    Future-proofing: a v2 export must not be silently parsed by v1 rules
    """
    out = tmp_path / "export.json"
    out.write_text(json.dumps({"export_version": 99, "entries": {}}))
    with pytest.raises(VaultFormatError):
        read_export_file(out)


def test_read_export_file_validates_rows(tmp_path: Path) -> None:
    """
    Verify a malformed entry row fails the whole import loudly

    We never trust the file's structure. An entry missing its required
    password field must raise VaultFormatError, not import a half-entry
    """
    out = tmp_path / "export.json"
    out.write_text(
        json.dumps({
            "export_version": 1,
            "entries": {
                "github": {
                    "username": "alice"
                }
            },
        })
    )
    with pytest.raises(VaultFormatError):
        read_export_file(out)

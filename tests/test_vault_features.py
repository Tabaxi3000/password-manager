"""
test_vault_features.py

Tests for the vault features added by the CHALLENGES.md exercises

Covers the parts of vault.py that the challenge work touched:

  - Entry's new fields (last_used_at, totp_secret) round-trip through
    save/unlock, and old vaults that predate them still open
  - record_usage stamps last_used_at without disturbing updated_at
  - needs_kdf_upgrade / upgrade_kdf — the transparent KDF strengthening
    that backs `pv`'s auto-upgrade-on-unlock behavior

The crypto here uses the fast TEST_KDF_PARAMETERS from conftest so the
Argon2 work stays in milliseconds
"""

# Standard library: build a "tampered"/old-shaped dict for from_dict.
import dataclasses

# Third-party: the test runner — pytest.raises in a couple of places.
import pytest

# Local: the crypto knobs. KdfParameters.defaults() is what the upgrade
# logic compares against; we also build a deliberately-stronger set.
from password_manager.crypto import KdfParameters
# Local: the vault surface under test.
from password_manager.vault import (
    Entry,
    UnlockedVault,
)


# =============================================================================
# Entry — new optional fields
# =============================================================================


def test_entry_defaults_new_fields_to_empty() -> None:
    """
    Verify a freshly built Entry has empty last_used_at and totp_secret

    Both fields are opt-in. A brand-new entry has never been "used" and
    carries no TOTP secret, so both default to the empty string
    """
    entry = Entry(username = "alice", password = "x")
    assert entry.last_used_at == ""
    assert entry.totp_secret == ""


def test_entry_from_dict_back_compat_without_new_fields() -> None:
    """
    Verify Entry.from_dict still loads a v1-shaped dict (no new fields)

    An old vault on disk predates last_used_at and totp_secret. Loading
    it must not crash — the new fields fill in as empty strings, exactly
    the way created_at/updated_at handle their absence
    """
    entry = Entry.from_dict({"username": "alice", "password": "x"})
    assert entry.last_used_at == ""
    assert entry.totp_secret == ""


def test_new_fields_round_trip_through_save_and_unlock(
    fresh_vault: UnlockedVault,
    master_password: str,
) -> None:
    """
    Verify last_used_at and totp_secret survive a save → unlock cycle

    The whole point of adding fields to a dataclass is that asdict()
    serializes them for free and from_dict reads them back. We confirm
    the encrypted round-trip preserves both
    """
    fresh_vault.add_entry(
        "github",
        Entry(
            username = "alice",
            password = "s3cret",
            totp_secret = "JBSWY3DPEHPK3PXP",
            last_used_at = "2026-01-01T00:00:00+00:00",
        ),
    )
    fresh_vault.save()

    reopened = UnlockedVault.unlock(fresh_vault.path, master_password)
    entry = reopened.entries["github"]
    assert entry.totp_secret == "JBSWY3DPEHPK3PXP"
    assert entry.last_used_at == "2026-01-01T00:00:00+00:00"


# =============================================================================
# record_usage — last_used_at tracking
# =============================================================================


def test_record_usage_sets_last_used_at(fresh_vault: UnlockedVault) -> None:
    """
    Verify record_usage stamps a non-empty last_used_at

    Before any get, last_used_at is empty. After record_usage it carries
    a timestamp — that is what lets `pv get` remember when a credential
    was last reached for
    """
    fresh_vault.add_entry("github", Entry(username = "a", password = "b"))
    assert fresh_vault.get_entry("github").last_used_at == ""

    refreshed = fresh_vault.record_usage("github")
    assert refreshed.last_used_at != ""
    # The stored entry is updated too, not just the returned copy
    assert fresh_vault.get_entry("github").last_used_at != ""


def test_record_usage_does_not_touch_updated_at(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify record_usage leaves updated_at unchanged

    Reading a credential is not editing it. If record_usage bumped
    updated_at, every `get` would masquerade as a modification and the
    "how stale is this password" signal would be useless
    """
    fresh_vault.add_entry("github", Entry(username = "a", password = "b"))
    original_updated = fresh_vault.get_entry("github").updated_at

    fresh_vault.record_usage("github")
    assert fresh_vault.get_entry("github").updated_at == original_updated


def test_record_usage_missing_raises(fresh_vault: UnlockedVault) -> None:
    """
    Verify record_usage on an unknown name raises EntryNotFoundError

    Same contract as get_entry — record_usage is "get plus a stamp", so
    a miss must fail the same loud way rather than silently no-op
    """
    from password_manager.vault import EntryNotFoundError
    with pytest.raises(EntryNotFoundError):
        fresh_vault.record_usage("nope")


# =============================================================================
# KDF auto-upgrade
# =============================================================================


def test_needs_kdf_upgrade_true_for_weak_params(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify a vault built with below-default KDF params reports it

    fresh_vault is created with TEST_KDF_PARAMETERS, which are far
    weaker than production defaults. So needs_kdf_upgrade() must be True
    """
    assert fresh_vault.needs_kdf_upgrade() is True


def test_needs_kdf_upgrade_false_at_defaults(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify a vault already at the current defaults does NOT need upgrade

    We swap the in-memory parameters to defaults() and confirm the check
    flips to False — a vault at (or above) defaults should be left alone
    """
    fresh_vault.kdf_parameters = KdfParameters.defaults()
    assert fresh_vault.needs_kdf_upgrade() is False


def test_needs_kdf_upgrade_false_when_stronger_than_defaults(
    fresh_vault: UnlockedVault,
) -> None:
    """
    Verify a vault tuned STRONGER than defaults is not flagged

    "Upgrading" a deliberately-hardened vault down to the defaults would
    actually weaken it. A vault stronger in every dimension must report
    no upgrade needed
    """
    defaults = KdfParameters.defaults()
    fresh_vault.kdf_parameters = dataclasses.replace(
        defaults,
        time_cost = defaults.time_cost + 1,
        memory_cost = defaults.memory_cost * 2,
    )
    assert fresh_vault.needs_kdf_upgrade() is False


def test_upgrade_kdf_rederives_to_defaults_and_keeps_data(
    fresh_vault: UnlockedVault,
    master_password: str,
) -> None:
    """
    Verify upgrade_kdf moves params to defaults, same password, data intact

    After the upgrade: the stored KDF parameters equal the defaults, the
    salt and key have rotated, the SAME master password still unlocks,
    and every entry survives. This is the core of transparent
    auto-upgrade
    """
    fresh_vault.add_entry("github", Entry(username = "a", password = "s3cret"))
    old_salt = fresh_vault.salt
    old_key = fresh_vault.key

    fresh_vault.upgrade_kdf(master_password)
    fresh_vault.save()

    assert fresh_vault.kdf_parameters == KdfParameters.defaults()
    assert fresh_vault.salt != old_salt
    assert fresh_vault.key != old_key
    assert not fresh_vault.needs_kdf_upgrade()

    reopened = UnlockedVault.unlock(fresh_vault.path, master_password)
    assert reopened.entries["github"].password == "s3cret"
    assert reopened.kdf_parameters == KdfParameters.defaults()

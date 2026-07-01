"""
test_cli.py

End-to-end tests for the new CLI commands, through Typer's CliRunner

These exercise the real command wiring — argument parsing, the unlock
helper, output streams — for the commands added by the challenge work:
search, count, get --show, add, export/import, backup/restore, totp

To keep them fast and non-interactive we monkeypatch two things:

  - KdfParameters.defaults() → the fast TEST params, so Argon2 runs in
    milliseconds AND the transparent KDF auto-upgrade stays quiet (the
    test vault is already "at defaults")
  - the master-password prompt helpers → return a fixed password, so no
    getpass/terminal interaction is needed

Everything else (entry prompts, the export "YES" confirmation) is fed
through CliRunner's `input=`
"""

# Standard library: `contextlib.suppress` to ignore a missing stderr
# stream, and regex to assert a TOTP code is six digits.
import contextlib
import re
from pathlib import Path

# Third-party: the test runner and Typer's in-process CLI invoker.
import pytest
from typer.testing import CliRunner

# Local: the Typer app and the helpers/constants the tests lean on.
from password_manager.crypto import KdfParameters
from password_manager.main import app
from password_manager import main as main_module
from password_manager.vault import Entry, UnlockedVault
from tests.conftest import TEST_KDF_PARAMETERS

MASTER = "correct horse battery staple"


def _combined_output(result: object) -> str:
    """
    Return stdout + stderr from a CliRunner result, across click versions

    Some click versions split stderr onto result.stderr; others fold it
    into result.output. We concatenate whatever is available so an
    assertion does not depend on which stream a message landed on
    """
    text = getattr(result, "output", "") or ""
    # stderr may not be captured separately (older click folds it into
    # output); suppress the resulting error rather than branch on version
    with contextlib.suppress(ValueError, AttributeError):
        text += result.stderr or ""  # type: ignore[attr-defined]
    return text


@pytest.fixture
def runner(monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    """
    A CliRunner with fast KDF params and stubbed password prompts
    """
    monkeypatch.setattr(
        KdfParameters,
        "defaults",
        classmethod(lambda cls: TEST_KDF_PARAMETERS),
    )
    monkeypatch.setattr(
        main_module,
        "_prompt_master_password",
        lambda prompt = "": MASTER,
    )
    monkeypatch.setattr(
        main_module,
        "_prompt_master_password_with_confirmation",
        lambda: MASTER,
    )
    return CliRunner()


def _make_vault(path: Path, **entries: Entry) -> None:
    """
    Create a vault at `path` (fast KDF) and add the given entries
    """
    vault = UnlockedVault.create(
        path,
        MASTER,
        kdf_parameters = TEST_KDF_PARAMETERS,
    )
    for name, entry in entries.items():
        vault.add_entry(name, entry)
    vault.save()


# =============================================================================
# count / search
# =============================================================================


def test_count_prints_bare_number(runner: CliRunner, tmp_path: Path) -> None:
    """
    Verify `pv count` prints just the number of entries
    """
    vault = tmp_path / "v.json"
    _make_vault(
        vault,
        github = Entry(username = "a", password = "p"),
        gitlab = Entry(username = "b", password = "q"),
    )
    result = runner.invoke(app, ["count", "--vault", str(vault)])
    assert result.exit_code == 0
    # The bare number is on its own line in stdout
    assert "2" in result.output.split()


def test_search_filters_by_substring(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    """
    Verify `pv search` lists only matching names, case-insensitively
    """
    vault = tmp_path / "v.json"
    _make_vault(
        vault,
        github = Entry(username = "a", password = "p"),
        gitlab = Entry(username = "b", password = "q"),
        bank = Entry(username = "c", password = "r"),
    )
    result = runner.invoke(app, ["search", "GIT", "--vault", str(vault)])
    out = _combined_output(result)
    assert result.exit_code == 0
    assert "github" in out
    assert "gitlab" in out
    assert "bank" not in out


def test_search_empty_query_rejected(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    """
    Verify `pv search "   "` is rejected rather than matching everything
    """
    vault = tmp_path / "v.json"
    _make_vault(vault, github = Entry(username = "a", password = "p"))
    result = runner.invoke(app, ["search", "   ", "--vault", str(vault)])
    assert result.exit_code == 1


# =============================================================================
# get --show / last_used
# =============================================================================


def test_get_masks_password_by_default(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    """
    Verify `pv get` hides the password unless --show is passed
    """
    vault = tmp_path / "v.json"
    _make_vault(
        vault,
        github = Entry(username = "alice", password = "hunter2-secret"),
    )

    hidden = runner.invoke(app, ["get", "github", "--vault", str(vault)])
    assert hidden.exit_code == 0
    assert "hunter2-secret" not in _combined_output(hidden)

    shown = runner.invoke(
        app,
        ["get", "github", "--show", "--vault", str(vault)],
    )
    assert shown.exit_code == 0
    assert "hunter2-secret" in _combined_output(shown)


def test_get_records_last_used(runner: CliRunner, tmp_path: Path) -> None:
    """
    Verify `pv get` stamps last_used_at and persists it

    After a get, reopening the vault shows a non-empty last_used_at on
    the entry — proof the command saved the mutation
    """
    vault = tmp_path / "v.json"
    _make_vault(
        vault,
        github = Entry(username = "alice", password = "p"),
    )
    runner.invoke(app, ["get", "github", "--vault", str(vault)])

    reopened = UnlockedVault.unlock(vault, MASTER)
    assert reopened.entries["github"].last_used_at != ""


# =============================================================================
# add (generate path: strength + totp prompt)
# =============================================================================


def test_add_generate_increments_count(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    """
    Verify `pv add --generate` adds an entry through the full prompt flow

    The generated password is strong, so the weak-password confirm never
    fires. The four input lines feed username, url, notes, and the
    (skipped) TOTP secret
    """
    vault = tmp_path / "v.json"
    _make_vault(vault)  # empty vault

    result = runner.invoke(
        app,
        ["add", "github", "--generate", "--vault", str(vault)],
        input = "alice\n\n\n\n",
    )
    assert result.exit_code == 0, _combined_output(result)

    reopened = UnlockedVault.unlock(vault, MASTER)
    assert "github" in reopened.entries
    assert reopened.entries["github"].username == "alice"


# =============================================================================
# export / import
# =============================================================================


def test_export_then_import_cli(runner: CliRunner, tmp_path: Path) -> None:
    """
    Verify the export → import CLI round trip moves entries across vaults
    """
    src_vault = tmp_path / "src.json"
    dst_vault = tmp_path / "dst.json"
    export_file = tmp_path / "export.json"
    _make_vault(
        src_vault,
        github = Entry(username = "alice", password = "p1"),
        gitlab = Entry(username = "bob", password = "p2"),
    )
    _make_vault(dst_vault)  # empty target

    # Export requires typing YES at the danger prompt (fed via input)
    exported = runner.invoke(
        app,
        ["export", str(export_file), "--vault", str(src_vault)],
        input = "YES\n",
    )
    assert exported.exit_code == 0, _combined_output(exported)
    assert export_file.exists()

    imported = runner.invoke(
        app,
        ["import", str(export_file), "--vault", str(dst_vault)],
    )
    assert imported.exit_code == 0, _combined_output(imported)

    reopened = UnlockedVault.unlock(dst_vault, MASTER)
    assert reopened.entries["github"].password == "p1"
    assert reopened.entries["gitlab"].password == "p2"


def test_export_aborts_without_yes(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    """
    Verify export writes nothing if the user does not type YES
    """
    vault = tmp_path / "v.json"
    export_file = tmp_path / "export.json"
    _make_vault(vault, github = Entry(username = "a", password = "p"))

    result = runner.invoke(
        app,
        ["export", str(export_file), "--vault", str(vault)],
        input = "no\n",
    )
    assert result.exit_code == 1
    assert not export_file.exists()


# =============================================================================
# backup / restore
# =============================================================================


def test_backup_then_restore_cli(runner: CliRunner, tmp_path: Path) -> None:
    """
    Verify `pv backup` then `pv restore` round-trips the live vault

    Snapshot, then change the live vault, then restore --yes. The
    restored vault must match the snapshot, not the later change
    """
    vault = tmp_path / "v.json"
    backups = tmp_path / "backups"
    _make_vault(vault, github = Entry(username = "alice", password = "p"))

    backed = runner.invoke(
        app,
        ["backup", "--vault", str(vault), "--backup-dir", str(backups)],
    )
    assert backed.exit_code == 0, _combined_output(backed)

    # Diverge the live vault from the snapshot
    live = UnlockedVault.unlock(vault, MASTER)
    live.add_entry("gitlab", Entry(username = "bob", password = "q"))
    live.save()

    # Find the snapshot filename and restore it
    snapshot = next(backups.glob("vault-*.json"))
    restored = runner.invoke(
        app,
        [
            "restore",
            snapshot.name,
            "--vault",
            str(vault),
            "--backup-dir",
            str(backups),
            "--yes",
        ],
    )
    assert restored.exit_code == 0, _combined_output(restored)

    reopened = UnlockedVault.unlock(vault, MASTER)
    assert "github" in reopened.entries
    assert "gitlab" not in reopened.entries


# =============================================================================
# totp
# =============================================================================


def test_totp_cli_prints_six_digits(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    """
    Verify `pv totp` prints a six-digit code for an entry with a secret
    """
    vault = tmp_path / "v.json"
    _make_vault(
        vault,
        github = Entry(
            username = "alice",
            password = "p",
            totp_secret = "JBSWY3DPEHPK3PXP",
        ),
    )
    result = runner.invoke(app, ["totp", "github", "--vault", str(vault)])
    assert result.exit_code == 0, _combined_output(result)
    # The bare code is on stdout; assert a 6-digit run appears
    assert re.search(r"\b\d{6}\b", result.output)


def test_totp_cli_no_secret_errors(
    runner: CliRunner,
    tmp_path: Path,
) -> None:
    """
    Verify `pv totp` on an entry without a TOTP secret exits non-zero
    """
    vault = tmp_path / "v.json"
    _make_vault(vault, github = Entry(username = "alice", password = "p"))
    result = runner.invoke(app, ["totp", "github", "--vault", str(vault)])
    assert result.exit_code == 1

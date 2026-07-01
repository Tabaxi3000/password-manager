"""
main.py

CLI entry point — wires the user's keyboard to the vault

Everything below is glue: take the arguments the user typed, prompt
for the master password without echoing it, call the right method on
UnlockedVault, and print results in a friendly format. The actual
work happens in vault.py and crypto.py

────────────────────────────────────────────────────────────────────
Why Typer
────────────────────────────────────────────────────────────────────
Typer turns a regular Python function into a CLI command, just by
reading its type hints and docstrings. Compare these two ways of
saying "add a `--length` option that defaults to 24"

  Manual argparse:
    parser.add_argument("--length", type=int, default=24,
                        help="Password length")

  Typer:
    length: Annotated[int, typer.Option(help="Password length")] = 24

Typer also generates --help text, validates types automatically, and
plays well with rich for colorful output

────────────────────────────────────────────────────────────────────
Master password handling
────────────────────────────────────────────────────────────────────
We use getpass.getpass() so the password never appears on screen as
the user types. We never accept the master password as a CLI flag —
that would leak it into shell history (`history` command) and into
process listings (`ps`). Pass-through-stdin is fine for scripting

────────────────────────────────────────────────────────────────────
Commands exposed
────────────────────────────────────────────────────────────────────
  init             — create a new empty vault (--verify re-unlocks it)
  add <name>       — add an entry (prompts for fields, scores password)
  get <name>       — show an entry's details (--show reveals password)
  list             — list every entry name
  search <substr>  — list entry names containing a substring
  count            — print just the number of entries (pipe-friendly)
  copy <name>      — copy an entry's password to the clipboard
  totp <name>      — print the current 2FA code for an entry
  delete <name>    — remove an entry
  change-password  — rotate the master password (re-encrypts vault)
  gen              — generate a random password (no vault touched)
  export <path>    — write all entries to a PLAINTEXT file (dangerous)
  import <path>    — read entries back from a plaintext export
  backup           — snapshot the encrypted vault file
  backups          — list snapshots
  restore <ref>    — overwrite the live vault from a snapshot

Connects to
  vault.py — instantiates UnlockedVault for read/write operations
  generator.py — used by `gen` and offered inside `add`
  constants.py — pulls prompt strings and default vault path
"""

# Standard library: `contextlib.suppress` lets us swallow a specific
# exception in one line — used when deleting a failed `init --verify`
# vault.
import contextlib
# Standard library: reads a password from the terminal WITHOUT
# echoing the characters as the user types — same trick `sudo` uses.
import getpass
# Standard library: `time.sleep` powers the `pv copy --clear-after`
# countdown before we wipe the clipboard.
import time
# Standard library: object-oriented filesystem paths — safer and
# more readable than gluing strings with `os.path.join`.
from pathlib import Path
# Standard library: lets us attach extra metadata (Typer Option/Argument
# specs) to a parameter's type hint without changing its type.
from typing import Annotated

# Third-party (Typer): the CLI framework. Turns a regular function
# into a subcommand with parsed args, help text, and auto-completion.
import typer
# Third-party (rich): the printer that draws colored output to the
# terminal — every user-facing message goes through this.
from rich.console import Console
# Third-party (rich): draws a bordered box — used for the welcome
# banner and the "vault created" confirmation panel.
from rich.panel import Panel
# Third-party (rich): builds the colored ASCII table that lists
# vault entries in the `list` command.
from rich.table import Table

# Local: pull every prompt string, error message, and default value
# from constants — main.py never holds magic strings of its own.
from password_manager.constants import (
    DEFAULT_BACKUP_DIRECTORY,
    DEFAULT_CLIPBOARD_CLEAR_SECONDS,
    DEFAULT_EXPORT_PATH,
    DEFAULT_GENERATED_PASSWORD_LENGTH,
    DEFAULT_MAX_BACKUPS,
    DEFAULT_VAULT_PATH,
    MASKED_PASSWORD_DISPLAY,
    MINIMUM_MASTER_PASSWORD_LENGTH,
    MSG_BACKUP_DONE,
    MSG_BACKUP_NOT_FOUND,
    MSG_BACKUP_PRUNED,
    MSG_CLIPBOARD_UNAVAILABLE,
    MSG_COPIED,
    MSG_COPY_CLEARED,
    MSG_ENTRY_ADDED,
    MSG_ENTRY_ALREADY_EXISTS,
    MSG_ENTRY_DELETED,
    MSG_ENTRY_NOT_FOUND,
    MSG_EXPORT_ABORTED,
    MSG_EXPORT_CONFIRM,
    MSG_EXPORT_DONE,
    MSG_EXPORT_WARNING,
    MSG_IMPORT_BAD_FILE,
    MSG_IMPORT_DONE,
    MSG_IMPORT_NOT_FOUND,
    MSG_KDF_UPGRADED,
    MSG_KDF_UPGRADING,
    MSG_MASTER_PASSWORD_CHANGED,
    MSG_MASTER_PASSWORD_EMPTY,
    MSG_MASTER_PASSWORD_TOO_SHORT,
    MSG_NO_BACKUPS,
    MSG_NO_MATCHES,
    MSG_PASSWORDS_DO_NOT_MATCH,
    MSG_RESTORE_CONFIRM,
    MSG_RESTORE_DONE,
    MSG_SEARCH_EMPTY_QUERY,
    MSG_TOTP_INVALID_SECRET,
    MSG_TOTP_NOT_CONFIGURED,
    MSG_VAULT_ALREADY_EXISTS,
    MSG_VAULT_CREATED,
    MSG_VAULT_EMPTY,
    MSG_VAULT_NOT_FOUND,
    MSG_VERIFY_FAILED,
    MSG_VERIFY_OK,
    MSG_WRONG_MASTER_PASSWORD,
    PROMPT_ENTRY_NOTES,
    PROMPT_ENTRY_TOTP,
    PROMPT_ENTRY_URL,
    PROMPT_ENTRY_USERNAME,
    PROMPT_MASTER_PASSWORD,
    PROMPT_MASTER_PASSWORD_CONFIRM,
    PROMPT_MASTER_PASSWORD_NEW,
    STRENGTH_WARN_AT_OR_BELOW,
)
# Local: the one crypto-layer error we want to translate into a
# friendly "wrong master password" message for the user.
from password_manager.crypto import WrongPasswordError
# Local: the password generator — its custom error type and the
# function that actually builds a random password.
from password_manager.generator import (
    PasswordTooShortError,
    generate_password,
)
# Local: every vault-layer name we need — the Entry record, the
# UnlockedVault class, the backup/export helpers, and every
# domain-specific error we catch.
from password_manager.vault import (
    Entry,
    EntryAlreadyExistsError,
    EntryNotFoundError,
    UnlockedVault,
    VaultAlreadyExistsError,
    VaultError,
    VaultFormatError,
    VaultNotFoundError,
    create_backup,
    export_entries,
    list_backups,
    read_export_file,
    restore_backup,
)
# Local: optional-feature helpers — clipboard copy, TOTP code
# generation, and password-strength scoring. Each degrades gracefully
# when its optional third-party library is absent.
from password_manager import clipboard
from password_manager.strength import score_password
from password_manager.totp import (
    TotpError,
    generate_totp,
    seconds_remaining,
)


# =============================================================================
# Typer app + consoles — module-level singletons
# =============================================================================
# Typer.app is the registry every @app.command() decorator attaches to.
# rich.Console handles colorful output. Both are created once and
# reused by every command
#
# We keep TWO consoles, one for each output stream. The convention
# is universal in CLI tools
#
#   stdout — the "result" of the command. Pipe-safe. Capturable
#   stderr — diagnostics, errors, progress. Always shown to the user
#
# Splitting them lets users redirect cleanly. `pv gen 32 | pbcopy`
# pipes ONLY the password into the clipboard, even if pv prints an
# error. `pv get foo 2>/dev/null` swallows error chatter without
# also swallowing the panel of credentials

app = typer.Typer(
    name = "pv",
    help = "Encrypted password manager (Argon2id + AES-256-GCM)",
    no_args_is_help = True,
    add_completion = False,
)
console = Console()
error_console = Console(stderr = True)


# Module-level switch for transparent KDF upgrades (see the callback
# below and `_unlock_or_exit`). A module global is the simplest way to
# let a top-level `--no-auto-upgrade` flag influence every command
# without threading the flag through each one's signature
_auto_upgrade_kdf = True


@app.callback()
def _global_options(
    no_auto_upgrade: Annotated[
        bool,
        typer.Option(
            "--no-auto-upgrade",
            help = (
                "Do not transparently re-derive old vaults with the "
                "current (stronger) Argon2 settings on unlock"
            ),
        ),
    ] = False,
) -> None:
    """
    Options that apply to every subcommand

    Typer runs this callback before dispatching to a command, so flags
    declared here sit BEFORE the subcommand on the command line:
    `pv --no-auto-upgrade get github`
    """
    global _auto_upgrade_kdf
    _auto_upgrade_kdf = not no_auto_upgrade


# =============================================================================
# Shared option type — every command takes --vault
# =============================================================================
# Annotated[T, typer.Option(...)] is how Typer reads option metadata
# without polluting the function signature. The Annotated wrapper is
# fully transparent at runtime — it only matters to Typer at startup
#
# We define the type alias once so every command takes the same flag

VaultPath = Annotated[
    Path,
    typer.Option(
        "--vault",
        "-v",
        help = "Path to the vault file",
        envvar = "PV_VAULT",
    ),
]


# =============================================================================
# Helpers — keep command bodies focused on flow, not plumbing
# =============================================================================


def _prompt_master_password(prompt: str = PROMPT_MASTER_PASSWORD) -> str:
    """
    Read a master password from the terminal without echoing it

    Wraps getpass so we can swap implementations later (e.g. read
    from stdin in non-interactive scripts) without touching every
    command. getpass falls back to a noisy "echo enabled" warning
    if the terminal does not support hidden input — that is the
    library's behavior, not ours
    """
    return getpass.getpass(prompt)


def _prompt_master_password_with_confirmation() -> str:
    """
    Prompt for a new master password twice, validate it, and return it

    Used by `init` and `change-password` to set or rotate the master
    password. Three checks happen before the password is returned

      1. Non-empty — an empty password "encrypts" the vault under no
         real secret. Anyone who steals the file can re-derive the
         same key from the public salt
      2. At least MINIMUM_MASTER_PASSWORD_LENGTH characters — a hard
         floor below which we refuse to proceed
      3. Confirmation match — both prompts must produce the same
         string, so a typo does not lock the user out of their vault
         the first time they try to unlock it

    Exits with code 1 on any of the above. The caller does not have
    to handle these cases — by the time this returns, the password
    is known good
    """
    first = _prompt_master_password(PROMPT_MASTER_PASSWORD_NEW)

    if not first:
        error_console.print(f"[red]{MSG_MASTER_PASSWORD_EMPTY}[/red]")
        raise typer.Exit(code = 1)

    if len(first) < MINIMUM_MASTER_PASSWORD_LENGTH:
        error_console.print(
            f"[red]"
            f"{MSG_MASTER_PASSWORD_TOO_SHORT.format(minimum=MINIMUM_MASTER_PASSWORD_LENGTH)}"
            f"[/red]"
        )
        raise typer.Exit(code = 1)

    second = _prompt_master_password(PROMPT_MASTER_PASSWORD_CONFIRM)
    if first != second:
        error_console.print(f"[red]{MSG_PASSWORDS_DO_NOT_MATCH}[/red]")
        raise typer.Exit(code = 1)

    return first


def _unlock_or_exit(
    path: Path,
    master_password: str,
    *,
    auto_upgrade: bool = True,
) -> UnlockedVault:
    """
    Open a vault, exiting cleanly on every kind of failure

    Each error gets the right message and the right exit code.
    `typer.Exit(code=N)` raises an exception that Typer turns into
    `sys.exit(N)` cleanly — we never call sys.exit ourselves

    Errors go through error_console (stderr); informational and
    success messages go through console (stdout). That split is
    what makes the CLI pipe-friendly

    Transparent KDF upgrade
    -----------------------
    After a successful unlock, if the vault's Argon2 parameters are
    below the current defaults (and the user has not passed
    `--no-auto-upgrade`), we re-derive the key with the stronger
    settings and save — same password, stronger lock. This is what
    real password managers do, and it is why the file stores its KDF
    parameters in the first place. The upgrade message goes to STDERR
    so it never pollutes a command's piped stdout (`pv count`, etc.).
    The `auto_upgrade` argument lets a command opt out — `change-password`
    does, because it is about to re-derive the key anyway
    """
    try:
        unlocked = UnlockedVault.unlock(path, master_password)
    except VaultNotFoundError:
        error_console.print(
            f"[red]{MSG_VAULT_NOT_FOUND.format(path=path)}[/red]"
        )
        raise typer.Exit(code = 1) from None
    except WrongPasswordError:
        error_console.print(f"[red]{MSG_WRONG_MASTER_PASSWORD}[/red]")
        raise typer.Exit(code = 1) from None
    except VaultFormatError as exc:
        error_console.print(f"[red]Vault file is invalid: {exc}[/red]")
        raise typer.Exit(code = 1) from None
    except VaultError as exc:
        error_console.print(f"[red]Vault error: {exc}[/red]")
        raise typer.Exit(code = 1) from None

    if auto_upgrade and _auto_upgrade_kdf and unlocked.needs_kdf_upgrade():
        # Warn BEFORE the second ~0.5s Argon2 pause so the user knows
        # why the tool is briefly busy on an operation they did not ask
        # for. We already hold the old key from unlock, so this pays the
        # derivation cost exactly once — for the new, stronger key
        error_console.print(f"[yellow]{MSG_KDF_UPGRADING}[/yellow]")
        unlocked.upgrade_kdf(master_password)
        unlocked.save()
        error_console.print(f"[green]{MSG_KDF_UPGRADED}[/green]")

    return unlocked


def _render_entry(name: str, entry: Entry, *, show: bool = False) -> Panel:
    """
    Format an entry as a rich Panel for terminal display

    A Panel is a bordered box. We list each field on its own line and
    let the terminal handle long values

    The password is HIDDEN by default (a row of bullets) and only shown
    when `show=True`. Secure-by-default: you opt in to revealing a
    secret on screen — the "someone is shoulder-surfing / I am
    screen-sharing" case real password managers ship for. The bullet
    string is a fixed width that carries NO information about the real
    password's length
    """
    if show:
        password_display = entry.password
    else:
        # Fixed-width mask + a hint that --show reveals the real value
        password_display = (
            f"{MASKED_PASSWORD_DISPLAY}  [dim](use --show to reveal)[/dim]"
        )

    body_lines = [
        f"[bold]username[/bold]   {entry.username}",
        f"[bold]password[/bold]   {password_display}",
    ]
    if entry.url:
        body_lines.append(f"[bold]url[/bold]        {entry.url}")
    if entry.notes:
        body_lines.append(f"[bold]notes[/bold]      {entry.notes}")
    # Never print the TOTP secret here — just note that one exists, and
    # point the user at the command that turns it into a live code
    if entry.totp_secret:
        body_lines.append(
            "[bold]totp[/bold]       "
            "[green]configured[/green] [dim](run `pv totp " + name + "`)[/dim]"
        )
    body_lines.append(f"[dim]created    {entry.created_at}[/dim]")
    body_lines.append(f"[dim]updated    {entry.updated_at}[/dim]")
    # Only show last-used once it has actually been set — an empty
    # string means "never read since we started tracking"
    if entry.last_used_at:
        body_lines.append(f"[dim]last used  {entry.last_used_at}[/dim]")
    return Panel(
        "\n".join(body_lines),
        title = name,
        border_style = "cyan",
    )


# =============================================================================
# Commands
# =============================================================================
# Each @app.command decorates a function as a CLI command. The
# function name becomes the command name (init → `pv init`)


@app.command()
def init(
    vault: VaultPath = DEFAULT_VAULT_PATH,
    verify: Annotated[
        bool,
        typer.Option(
            "--verify",
            "-V",
            help = (
                "After creating, immediately re-unlock to prove the "
                "vault is readable (adds one ~0.5s Argon2 pass)"
            ),
        ),
    ] = False,
) -> None:
    """
    Create a new empty vault at --vault (or PV_VAULT or default path)
    """
    # The pre-check is a UX nicety: it lets us refuse without
    # prompting for a password we would only throw away. The check
    # inside create() is the AUTHORITATIVE one — between this check
    # and the prompts finishing, another process could have created
    # the vault, and we still need to handle that race
    if vault.exists():
        error_console.print(
            f"[red]{MSG_VAULT_ALREADY_EXISTS.format(path=vault)}[/red]"
        )
        raise typer.Exit(code = 1)

    master = _prompt_master_password_with_confirmation()
    try:
        # The create() call writes the empty vault and returns an
        # UnlockedVault. We have nothing else to do with it, so we
        # use `with` purely to drop the AES key right away
        with UnlockedVault.create(vault, master):
            pass
    except VaultAlreadyExistsError:
        error_console.print(
            f"[red]{MSG_VAULT_ALREADY_EXISTS.format(path=vault)}[/red]"
        )
        raise typer.Exit(code = 1) from None

    # Defense in depth: prove the write path produced a file the read
    # path can actually open, BEFORE the user walks away trusting it.
    # This is opt-in because it costs a second full Argon2 derivation.
    # If it fails, something is badly wrong — refuse to leave a vault
    # we cannot read sitting on disk pretending to be fine
    if verify:
        try:
            with UnlockedVault.unlock(vault, master):
                pass
        except (VaultError, WrongPasswordError):
            with contextlib.suppress(FileNotFoundError):
                vault.unlink()
            error_console.print(f"[red]{MSG_VERIFY_FAILED}[/red]")
            raise typer.Exit(code = 1) from None
        console.print(f"[green]{MSG_VERIFY_OK}[/green]")

    console.print(f"[green]{MSG_VAULT_CREATED.format(path=vault)}[/green]")


@app.command(name = "list")
def list_entries(vault: VaultPath = DEFAULT_VAULT_PATH) -> None:
    """
    Print every entry name in the vault, one per line
    """
    master = _prompt_master_password()
    # `with` ensures the AES key and plaintext entries are dropped
    # as soon as the table has been printed. We render INSIDE the
    # block because we still need to read the entries
    with _unlock_or_exit(vault, master) as unlocked:
        names = unlocked.names()
        if not names:
            console.print(f"[yellow]{MSG_VAULT_EMPTY}[/yellow]")
            return

        table = Table(title = f"Entries in {vault}", show_lines = False)
        table.add_column("name", style = "cyan", no_wrap = True)
        table.add_column("username", style = "white")
        table.add_column("updated", style = "dim")
        for name in names:
            entry = unlocked.entries[name]
            table.add_row(name, entry.username, entry.updated_at)
        console.print(table)


@app.command()
def get(
    name: Annotated[str,
                    typer.Argument(help = "Entry name to retrieve")],
    vault: VaultPath = DEFAULT_VAULT_PATH,
    show: Annotated[
        bool,
        typer.Option(
            "--show",
            "-s",
            help = "Reveal the password (hidden by default)",
        ),
    ] = False,
) -> None:
    """
    Show every field of one entry by name

    The password is hidden behind bullets unless you pass --show. Each
    `get` also stamps the entry's last_used_at and saves — so the vault
    remembers when you last reached for each credential
    """
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        try:
            # record_usage looks the entry up, stamps last_used_at, and
            # returns the refreshed copy. It raises EntryNotFoundError
            # if the name is unknown, same as get_entry would
            entry = unlocked.record_usage(name)
        except EntryNotFoundError:
            error_console.print(
                f"[red]{MSG_ENTRY_NOT_FOUND.format(name=name)}[/red]"
            )
            raise typer.Exit(code = 1) from None
        # `get` now MUTATES the vault (last_used_at), so we must save
        # before the `with` block drops the key. This is the documented
        # trade-off: a `get` is no longer a pure read of the file
        unlocked.save()
        # entry is a frozen Entry instance — its fields remain
        # readable after the vault closes, but we still render
        # inside the block to keep the lifecycle obvious
        console.print(_render_entry(name, entry, show = show))


@app.command()
def add(
    name: Annotated[str,
                    typer.Argument(help = "Entry name (must be unique)")],
    vault: VaultPath = DEFAULT_VAULT_PATH,
    force: Annotated[
        bool,
        typer.Option("--force",
                     "-f",
                     help = "Overwrite if exists"),
    ] = False,
    generate: Annotated[
        bool,
        typer.Option(
            "--generate",
            "-g",
            help = "Generate a random password instead of prompting",
        ),
    ] = False,
    length: Annotated[
        int,
        typer.Option(
            "--length",
            "-n",
            help = "Length when --generate is used",
        ),
    ] = DEFAULT_GENERATED_PASSWORD_LENGTH,
) -> None:
    """
    Add (or overwrite with --force) an entry in the vault
    """
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        # Collect entry fields. We use plain input() for
        # username/url/notes because they are not secret — getpass
        # for the entry's password
        username = input(PROMPT_ENTRY_USERNAME.format(entry = name))

        if generate:
            try:
                password = generate_password(length)
            except PasswordTooShortError as exc:
                error_console.print(f"[red]{exc}[/red]")
                raise typer.Exit(code = 1) from None
            console.print(f"[green]Generated password:[/green] {password}")
        else:
            password = _prompt_master_password(
                f"Password for {name} (hidden): "
            )

        # Score the password BEFORE it is saved, so a weak one can be
        # reconsidered without a delete-and-re-add. We WARN, we do not
        # BLOCK — the user may have a good reason for a weak password
        score, label, color = score_password(password)
        console.print(
            f"Password strength: [{color}]{label}[/{color}] ({score}/4)"
        )
        if score <= STRENGTH_WARN_AT_OR_BELOW and not typer.confirm(
            "That password is weak. Save it anyway?"
        ):
            error_console.print("[yellow]Aborted — entry not saved[/yellow]")
            raise typer.Exit(code = 1)

        url = input(PROMPT_ENTRY_URL).strip()
        notes = input(PROMPT_ENTRY_NOTES).strip()

        # Optional TOTP secret. It lives INSIDE the encrypted vault as a
        # field on the entry — it is at least as sensitive as the
        # password. We validate it now (cheaply) so a bad secret fails
        # at add-time, not later when the user urgently needs a code
        totp_secret = input(PROMPT_ENTRY_TOTP).strip()
        if totp_secret:
            try:
                generate_totp(totp_secret)
            except TotpError as exc:
                error_console.print(
                    f"[red]TOTP secret is invalid: {exc}[/red]"
                )
                raise typer.Exit(code = 1) from None

        entry = Entry(
            username = username,
            password = password,
            url = url,
            notes = notes,
            totp_secret = totp_secret,
        )

        try:
            unlocked.add_entry(name, entry, force = force)
        except EntryAlreadyExistsError:
            error_console.print(
                f"[red]{MSG_ENTRY_ALREADY_EXISTS.format(name=name)}[/red]"
            )
            raise typer.Exit(code = 1) from None
        except ValueError as exc:
            # Empty / whitespace entry name caught by add_entry's
            # validation. Surface it as a clean error
            error_console.print(f"[red]{exc}[/red]")
            raise typer.Exit(code = 1) from None

        unlocked.save()
    console.print(f"[green]{MSG_ENTRY_ADDED.format(name=name)}[/green]")


@app.command()
def delete(
    name: Annotated[str,
                    typer.Argument(help = "Entry name to delete")],
    vault: VaultPath = DEFAULT_VAULT_PATH,
) -> None:
    """
    Remove an entry by name
    """
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        try:
            unlocked.delete_entry(name)
        except EntryNotFoundError:
            error_console.print(
                f"[red]{MSG_ENTRY_NOT_FOUND.format(name=name)}[/red]"
            )
            raise typer.Exit(code = 1) from None

        unlocked.save()
    console.print(f"[green]{MSG_ENTRY_DELETED.format(name=name)}[/green]")


@app.command()
def gen(
    length: Annotated[
        int,
        typer.Argument(help = "Password length"),
    ] = DEFAULT_GENERATED_PASSWORD_LENGTH,
    no_symbols: Annotated[
        bool,
        typer.Option("--no-symbols",
                     help = "Letters and digits only"),
    ] = False,
    no_digits: Annotated[
        bool,
        typer.Option("--no-digits",
                     help = "Letters and symbols only"),
    ] = False,
    no_uppercase: Annotated[
        bool,
        typer.Option("--no-uppercase",
                     help = "No uppercase letters"),
    ] = False,
) -> None:
    """
    Print a fresh random password and exit (no vault required)
    """
    try:
        password = generate_password(
            length,
            use_lowercase = True,
            use_uppercase = not no_uppercase,
            use_digits = not no_digits,
            use_symbols = not no_symbols,
        )
    except (PasswordTooShortError, ValueError) as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code = 1) from None

    # Plain print() so the output is pipe-friendly:
    #   PASSWORD=$(pv gen 32)
    print(password)


@app.command(name = "change-password")
def change_password(vault: VaultPath = DEFAULT_VAULT_PATH) -> None:
    """
    Change the master password (re-encrypts the vault end-to-end)

    The whole reason the on-disk format stores the salt and KDF
    parameters next to the ciphertext is so this operation is
    possible. We unlock with the OLD password, derive a fresh salt
    + key from the NEW password, and save — which re-encrypts every
    entry under the new key. Old vault file content is replaced
    atomically by the save() pattern, so a crash mid-rotation
    leaves the user with either the old or the new vault, never
    half of either
    """
    current = _prompt_master_password("Current master password: ")
    # auto_upgrade=False: we are about to re-derive the key under a new
    # password anyway, which already lands on the current defaults.
    # Letting the transparent upgrade also fire here would derive the
    # key twice for no benefit
    with _unlock_or_exit(vault, current, auto_upgrade = False) as unlocked:
        new_password = _prompt_master_password_with_confirmation()
        unlocked.change_master_password(new_password)
        unlocked.save()
    console.print(
        f"[green]"
        f"{MSG_MASTER_PASSWORD_CHANGED.format(path=vault)}"
        f"[/green]"
    )


# =============================================================================
# search / count — read-only query commands
# =============================================================================


@app.command()
def search(
    query: Annotated[
        str,
        typer.Argument(help = "Substring to match against entry names"),
    ],
    vault: VaultPath = DEFAULT_VAULT_PATH,
) -> None:
    """
    List entry names that contain a substring (case-insensitive)

    Like `list`, but filtered. An empty query is rejected rather than
    treated as "match everything" — returning every entry for an empty
    search would be a surprising footgun
    """
    # Reject the empty query BEFORE prompting for a password we would
    # only throw away
    if not query.strip():
        error_console.print(f"[red]{MSG_SEARCH_EMPTY_QUERY}[/red]")
        raise typer.Exit(code = 1)

    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        needle = query.lower()
        matches = [
            name for name in unlocked.names() if needle in name.lower()
        ]
        if not matches:
            error_console.print(
                f"[yellow]{MSG_NO_MATCHES.format(query=query)}[/yellow]"
            )
            return

        table = Table(
            title = f"Entries matching '{query}'",
            show_lines = False,
        )
        table.add_column("name", style = "cyan", no_wrap = True)
        table.add_column("username", style = "white")
        table.add_column("updated", style = "dim")
        for name in matches:
            entry = unlocked.entries[name]
            table.add_row(name, entry.username, entry.updated_at)
        console.print(table)


@app.command()
def count(vault: VaultPath = DEFAULT_VAULT_PATH) -> None:
    """
    Print just the number of entries — useful in shell scripts

    Output is a bare number plus a newline, nothing else, so it pipes
    cleanly: `if [ "$(pv count)" -eq 0 ]; then ...`. An empty vault
    prints `0`, not a friendly "vault is empty" message
    """
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        total = len(unlocked.entries)
    # Plain print() — NOT console.print() — so no rich markup or
    # decoration leaks into the piped output
    print(total)


# =============================================================================
# copy — put a password on the clipboard without printing it
# =============================================================================


@app.command()
def copy(
    name: Annotated[str,
                    typer.Argument(help = "Entry whose password to copy")],
    vault: VaultPath = DEFAULT_VAULT_PATH,
    clear_after: Annotated[
        int,
        typer.Option(
            "--clear-after",
            "-c",
            help = (
                "Seconds to wait, then wipe the clipboard "
                "(0 = leave it; requires keeping this window open)"
            ),
        ),
    ] = DEFAULT_CLIPBOARD_CLEAR_SECONDS,
) -> None:
    """
    Copy an entry's password to the system clipboard (never prints it)

    The clipboard is shared and sticky, so this is a real security
    trade-off: the password never hits your scrollback or shell
    history, but it does sit on the clipboard until something
    overwrites it. `--clear-after N` blocks for N seconds and then
    wipes it
    """
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        try:
            entry = unlocked.get_entry(name)
        except EntryNotFoundError:
            error_console.print(
                f"[red]{MSG_ENTRY_NOT_FOUND.format(name=name)}[/red]"
            )
            raise typer.Exit(code = 1) from None
        # Grab the password into a local before the vault closes. This
        # is the one place we deliberately let a plaintext password
        # outlive the unlocked vault — there is no other way to hand it
        # to the clipboard
        password = entry.password

    try:
        clipboard.copy(password)
    except clipboard.ClipboardError:
        error_console.print(f"[red]{MSG_CLIPBOARD_UNAVAILABLE}[/red]")
        raise typer.Exit(code = 1) from None

    console.print(f"[green]{MSG_COPIED.format(name=name)}[/green]")

    if clear_after > 0:
        error_console.print(
            f"[dim]Clipboard clears in {clear_after}s — "
            f"keep this window open (Ctrl-C to keep it)[/dim]"
        )
        try:
            time.sleep(clear_after)
        except KeyboardInterrupt:
            # User wants to keep the clipboard — leave it intact and exit
            error_console.print("\n[dim]Left the clipboard intact[/dim]")
            raise typer.Exit(code = 0) from None
        clipboard.clear()
        console.print(f"[green]{MSG_COPY_CLEARED}[/green]")


# =============================================================================
# totp — generate a 2FA code from a stored TOTP secret
# =============================================================================


@app.command()
def totp(
    name: Annotated[str,
                    typer.Argument(help = "Entry whose TOTP code to print")],
    vault: VaultPath = DEFAULT_VAULT_PATH,
) -> None:
    """
    Print the current 6-digit TOTP code for an entry

    The code goes to stdout on its own line (pipe-friendly); the
    "valid for N more seconds" hint goes to stderr so it does not
    pollute a pipe. If the current code is about to roll over, you can
    see it and wait for the next window
    """
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        try:
            entry = unlocked.get_entry(name)
        except EntryNotFoundError:
            error_console.print(
                f"[red]{MSG_ENTRY_NOT_FOUND.format(name=name)}[/red]"
            )
            raise typer.Exit(code = 1) from None
        secret = entry.totp_secret

    if not secret:
        error_console.print(
            f"[yellow]{MSG_TOTP_NOT_CONFIGURED.format(name=name)}[/yellow]"
        )
        raise typer.Exit(code = 1)

    try:
        code = generate_totp(secret)
    except TotpError as exc:
        error_console.print(
            f"[red]{MSG_TOTP_INVALID_SECRET.format(name=name, error=exc)}[/red]"
        )
        raise typer.Exit(code = 1) from None

    remaining = seconds_remaining()
    # Bare code to stdout so `pv totp github` can be piped; the validity
    # hint to stderr so it never lands in the pipe
    print(code)
    error_console.print(f"[dim](valid for {remaining} more seconds)[/dim]")


# =============================================================================
# export / import — plaintext migration in and out
# =============================================================================


@app.command()
def export(
    path: Annotated[
        Path,
        typer.Argument(help = "Where to write the PLAINTEXT export"),
    ] = DEFAULT_EXPORT_PATH,
    vault: VaultPath = DEFAULT_VAULT_PATH,
    force: Annotated[
        bool,
        typer.Option("--force",
                     "-f",
                     help = "Overwrite an existing export file"),
    ] = False,
) -> None:
    """
    Export every entry to a PLAINTEXT JSON file (dangerous, on purpose)

    Migration in and out is a real need (you switch tools, you lose a
    phone), but a plaintext credentials file is exactly what this tool
    exists to avoid. So we make you look at a red warning and type YES
    before anything is written, default the file to the current
    directory (not your sticky home dir), and write it 0600
    """
    if path.exists() and not force:
        error_console.print(
            f"[red]Refusing to overwrite {path} — pass --force[/red]"
        )
        raise typer.Exit(code = 1)

    # A loud, unmissable warning BEFORE we ask for anything else
    error_console.print(
        Panel(
            MSG_EXPORT_WARNING.format(path = path),
            title = "DANGER — PLAINTEXT EXPORT",
            border_style = "red",
        )
    )
    confirmation = input(f"{MSG_EXPORT_CONFIRM}: ")
    if confirmation != "YES":
        error_console.print(f"[yellow]{MSG_EXPORT_ABORTED}[/yellow]")
        raise typer.Exit(code = 1)

    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        written = export_entries(path, unlocked.entries)

    plural = "y" if written == 1 else "ies"
    console.print(
        f"[green]"
        f"{MSG_EXPORT_DONE.format(count=written, plural=plural, path=path)}"
        f"[/green]"
    )


@app.command(name = "import")
def import_entries(
    path: Annotated[
        Path,
        typer.Argument(help = "Plaintext export file to import"),
    ],
    vault: VaultPath = DEFAULT_VAULT_PATH,
    force: Annotated[
        bool,
        typer.Option(
            "--force",
            "-f",
            help = "Overwrite entries that already exist (default: skip)",
        ),
    ] = False,
) -> None:
    """
    Import entries from a plaintext export file

    Every row is validated the same way a decrypted vault is — we do
    not trust the file's structure just because it claims to be ours.
    Entries that already exist are SKIPPED by default; --force
    overwrites them
    """
    master = _prompt_master_password()
    with _unlock_or_exit(vault, master) as unlocked:
        try:
            incoming = read_export_file(path)
        except VaultNotFoundError:
            error_console.print(
                f"[red]{MSG_IMPORT_NOT_FOUND.format(path=path)}[/red]"
            )
            raise typer.Exit(code = 1) from None
        except VaultFormatError as exc:
            error_console.print(
                f"[red]{MSG_IMPORT_BAD_FILE.format(error=exc)}[/red]"
            )
            raise typer.Exit(code = 1) from None

        added = 0
        skipped = 0
        for name, entry in incoming.items():
            try:
                unlocked.add_entry(name, entry, force = force)
                added += 1
            except EntryAlreadyExistsError:
                # Already present and no --force: leave the existing one
                skipped += 1
            except ValueError:
                # A name the file carried that our validator rejects
                # (empty, surrounding whitespace). Skip it rather than
                # abort the whole import
                skipped += 1
        unlocked.save()

    plural = "y" if added == 1 else "ies"
    console.print(
        MSG_IMPORT_DONE.format(added = added, plural = plural, skipped = skipped)
    )


# =============================================================================
# backup / restore — versioned encrypted snapshots
# =============================================================================


@app.command()
def backup(
    vault: VaultPath = DEFAULT_VAULT_PATH,
    backup_dir: Annotated[
        Path,
        typer.Option("--backup-dir",
                     help = "Where snapshots are kept"),
    ] = DEFAULT_BACKUP_DIRECTORY,
    keep: Annotated[
        int,
        typer.Option("--keep",
                     help = "How many snapshots to retain"),
    ] = DEFAULT_MAX_BACKUPS,
) -> None:
    """
    Snapshot the encrypted vault into a timestamped backup file

    No master password needed — a backup is a byte-for-byte copy of the
    already-encrypted file, so it is exactly as safe (or unsafe) as the
    live vault. Older snapshots beyond --keep are pruned
    """
    try:
        backup_path, pruned = create_backup(
            vault,
            backup_dir,
            max_backups = keep,
        )
    except VaultNotFoundError:
        error_console.print(
            f"[red]{MSG_VAULT_NOT_FOUND.format(path=vault)}[/red]"
        )
        raise typer.Exit(code = 1) from None
    except ValueError as exc:
        error_console.print(f"[red]{exc}[/red]")
        raise typer.Exit(code = 1) from None

    console.print(f"[green]{MSG_BACKUP_DONE.format(path=backup_path)}[/green]")
    if pruned:
        plural = "" if len(pruned) == 1 else "s"
        error_console.print(
            f"[dim]{MSG_BACKUP_PRUNED.format(count=len(pruned), plural=plural)}[/dim]"
        )


@app.command(name = "backups")
def list_backups_command(
    backup_dir: Annotated[
        Path,
        typer.Option("--backup-dir",
                     help = "Where snapshots are kept"),
    ] = DEFAULT_BACKUP_DIRECTORY,
) -> None:
    """
    List available backup snapshots, newest first
    """
    snapshots = list_backups(backup_dir)
    if not snapshots:
        error_console.print(
            f"[yellow]{MSG_NO_BACKUPS.format(path=backup_dir)}[/yellow]"
        )
        return

    table = Table(title = f"Backups in {backup_dir}")
    table.add_column("snapshot", style = "cyan", no_wrap = True)
    table.add_column("size", style = "dim", justify = "right")
    for snapshot in snapshots:
        table.add_row(snapshot.name, f"{snapshot.stat().st_size} B")
    console.print(table)


@app.command()
def restore(
    ref: Annotated[
        str,
        typer.Argument(
            help = "Backup filename or timestamp substring to restore",
        ),
    ],
    vault: VaultPath = DEFAULT_VAULT_PATH,
    backup_dir: Annotated[
        Path,
        typer.Option("--backup-dir",
                     help = "Where snapshots are kept"),
    ] = DEFAULT_BACKUP_DIRECTORY,
    yes: Annotated[
        bool,
        typer.Option("--yes",
                     "-y",
                     help = "Skip the overwrite confirmation"),
    ] = False,
) -> None:
    """
    Overwrite the live vault with a backup snapshot

    `ref` can be a full snapshot filename or any unambiguous substring
    of one (a timestamp works). The backup is validated as a real vault
    BEFORE the live file is touched, and the overwrite is atomic
    """
    matches = [p for p in list_backups(backup_dir) if ref in p.name]
    if not matches:
        error_console.print(
            f"[red]{MSG_BACKUP_NOT_FOUND.format(ref=ref, path=backup_dir)}[/red]"
        )
        raise typer.Exit(code = 1)
    if len(matches) > 1:
        names = ", ".join(p.name for p in matches)
        error_console.print(
            f"[red]'{ref}' is ambiguous — matches: {names}[/red]"
        )
        raise typer.Exit(code = 1)

    source = matches[0]
    if not yes and not typer.confirm(
        MSG_RESTORE_CONFIRM.format(dst = vault)
    ):
        error_console.print("[yellow]Restore aborted[/yellow]")
        raise typer.Exit(code = 1)

    try:
        restore_backup(source, vault)
    except (VaultNotFoundError, VaultFormatError) as exc:
        error_console.print(f"[red]Cannot restore: {exc}[/red]")
        raise typer.Exit(code = 1) from None

    console.print(
        f"[green]{MSG_RESTORE_DONE.format(src=source.name, dst=vault)}[/green]"
    )

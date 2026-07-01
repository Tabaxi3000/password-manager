"""
constants.py

Every "magic number" and fixed string the project uses, in one place

A "constant" is a value that never changes while the program runs
Beginners often hard-code numbers like `length = 16` directly into
the code that uses them — and then six months later, nobody remembers
why 16. By collecting every constant up here with a name and a
comment explaining its meaning, the rest of the codebase becomes
self-documenting

Three big buckets live here

1. Crypto parameters — sizes and tuning knobs for Argon2id (the key
   derivation function) and AES-256-GCM (the encryption). These are
   chosen based on current OWASP and NIST guidance. If you ever
   need to bump them in five years, you change them HERE and nowhere
   else

2. Vault file format — the schema version, JSON keys, and default
   file location. Storing the format version means future versions
   of this code can still read today's vaults

3. CLI strings — prompts, error messages, success messages. Kept
   here so they are easy to translate or re-word later

Connects to
  crypto.py — imports KDF and cipher constants
  vault.py — imports format constants and vault path defaults
  main.py — imports prompt and message strings
"""

# Standard library: object-oriented filesystem paths — safer and
# more readable than gluing strings with `os.path.join`.
from pathlib import Path
# Standard library: a type hint that marks a variable as a constant —
# mypy will reject any later attempt to reassign it.
from typing import Final


# =============================================================================
# Argon2id — Key Derivation Function parameters
# =============================================================================
# Argon2id turns a human password into a cryptographic key
# It is deliberately slow and memory-hungry to defeat brute-force
# attacks. These three knobs control HOW slow and HOW memory-hungry
#
# These values are informed by the OWASP Password Storage Cheat
# Sheet, but tuned for a single-user local password manager. OWASP's
# server-oriented configurations use parallelism=1 because a server
# parallelizes ACROSS many simultaneous logins. We use parallelism=4
# because a single user benefits from the speedup on their own
# machine — and an attacker gets the same speedup, so the security
# trade-off is net-neutral. Memory at 64 MiB is comfortably above
# every OWASP profile, which is what makes GPU brute-force expensive

# Number of passes Argon2 makes over its memory buffer
# More passes = slower derivation = harder to brute-force
# 3 is a strong choice for interactive use on modern CPUs
ARGON2_TIME_COST: Final[int] = 3

# Memory used per derivation, in kibibytes (1 KiB = 1024 bytes)
# 65536 KiB = 64 MiB. This defeats GPU/ASIC attackers because
# they have lots of compute but limited fast memory per core
ARGON2_MEMORY_KIB: Final[int] = 65536

# How many parallel threads Argon2 may use
# 4 is a safe default that works on every modern CPU
ARGON2_PARALLELISM: Final[int] = 4

# Salt length in bytes. The salt is random data mixed in with the
# password before hashing — it makes two identical passwords produce
# DIFFERENT keys, so attackers cannot precompute results
# 16 bytes (128 bits) is the standard recommendation
SALT_LENGTH_BYTES: Final[int] = 16

# Argon2 algorithmic invariants — the values below which the math
# does not even make sense. We use these to validate parameters
# loaded from a vault file on disk, so a corrupted or hand-edited
# file cannot make us call Argon2 with nonsense
#   - time_cost >= 1: at least one pass over memory
#   - parallelism >= 1: at least one lane
#   - memory_cost >= 8 * parallelism: Argon2's hard floor (each lane
#     needs at least 8 KiB of memory to function)
ARGON2_TIME_COST_MIN: Final[int] = 1
ARGON2_PARALLELISM_MIN: Final[int] = 1
ARGON2_MEMORY_KIB_PER_LANE_MIN: Final[int] = 8


# =============================================================================
# AES-256-GCM — Symmetric encryption parameters
# =============================================================================
# AES-256-GCM is the encryption algorithm we use to scramble vault
# contents. "256" means a 256-bit key. "GCM" is a "mode" that adds
# tamper-detection — if anyone changes one byte of the ciphertext,
# decryption will refuse and raise an error

# Key size in bytes. AES-256 wants exactly 32 bytes (256 bits)
# This is also what we ask Argon2 to produce when deriving the key
KEY_LENGTH_BYTES: Final[int] = 32

# Nonce ("number used once") size in bytes
# A nonce is a random value generated FRESH for every encryption
# Reusing a nonce with the same key is catastrophic for GCM —
# it leaks plaintext. So we generate a new 12-byte nonce every save
# 12 bytes is the GCM-recommended size (NIST SP 800-38D)
NONCE_LENGTH_BYTES: Final[int] = 12


# =============================================================================
# Vault file format
# =============================================================================
# The vault is stored as a single JSON file. The structure looks
# roughly like this (base64 fields shown as <...>)
#
#   {
#     "version": 1,
#     "kdf": {
#       "name": "argon2id",
#       "salt": "<base64>",
#       "time_cost": 3,
#       "memory_cost": 65536,
#       "parallelism": 4
#     },
#     "cipher": {
#       "name": "aes-256-gcm",
#       "nonce": "<base64>",
#       "ciphertext": "<base64>"
#     }
#   }
#
# Storing kdf params IN the file (not just in code) lets us bump
# defaults later without breaking old vaults — the file says how
# it was encrypted, and we believe it

# Bump this when the on-disk format changes incompatibly
VAULT_FORMAT_VERSION: Final[int] = 1

# Top-level JSON keys
VAULT_KEY_VERSION: Final[str] = "version"
VAULT_KEY_KDF: Final[str] = "kdf"
VAULT_KEY_CIPHER: Final[str] = "cipher"

# KDF section keys
KDF_KEY_NAME: Final[str] = "name"
KDF_KEY_SALT: Final[str] = "salt"
KDF_KEY_TIME_COST: Final[str] = "time_cost"
KDF_KEY_MEMORY_COST: Final[str] = "memory_cost"
KDF_KEY_PARALLELISM: Final[str] = "parallelism"

# Cipher section keys
CIPHER_KEY_NAME: Final[str] = "name"
CIPHER_KEY_NONCE: Final[str] = "nonce"
CIPHER_KEY_CIPHERTEXT: Final[str] = "ciphertext"

# Algorithm names written into the file (for self-documentation
# and so future versions can switch without breaking old vaults)
KDF_NAME_ARGON2ID: Final[str] = "argon2id"
CIPHER_NAME_AES_256_GCM: Final[str] = "aes-256-gcm"

# File mode: 0o600 means "owner can read+write, nobody else can
# touch it." Octal in Python is written 0o<digits>. We set this on
# the vault file the moment we create it
VAULT_FILE_MODE: Final[int] = 0o600

# Default location: ~/.password-vault/vault.json
# Path.home() resolves to /home/<user> on Linux, C:/Users/<user>
# on Windows, /Users/<user> on macOS
DEFAULT_VAULT_DIRECTORY: Final[Path] = Path.home() / ".password-vault"
DEFAULT_VAULT_FILENAME: Final[str] = "vault.json"
DEFAULT_VAULT_PATH: Final[Path] = (
    DEFAULT_VAULT_DIRECTORY / DEFAULT_VAULT_FILENAME
)


# =============================================================================
# Password generator defaults
# =============================================================================
# When the user runs `pv gen` to generate a random password, these
# are the defaults. Everything is overridable on the command line

# Default length when the user does not specify one
DEFAULT_GENERATED_PASSWORD_LENGTH: Final[int] = 24

# Minimum length we will allow. Passwords shorter than this are
# weak enough to brute-force in reasonable time
MINIMUM_GENERATED_PASSWORD_LENGTH: Final[int] = 8

# Minimum length for the MASTER password (the one that locks the
# whole vault). This is a floor, not a recommendation — users
# should pick something much longer. We reject anything shorter
# than this to prevent the obvious footgun of an empty or trivial
# master password silently "encrypting" the vault under no real
# secret. 8 mirrors NIST SP 800-63B's minimum for memorized secrets
MINIMUM_MASTER_PASSWORD_LENGTH: Final[int] = 8

# Character pools the generator can pick from
LOWERCASE_LETTERS: Final[str] = "abcdefghijklmnopqrstuvwxyz"
UPPERCASE_LETTERS: Final[str] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
DIGITS: Final[str] = "0123456789"

# Symbols deliberately exclude characters that confuse copy-paste
# (quotes, backticks) or get eaten by shells (backslash, dollar)
SAFE_SYMBOLS: Final[str] = "!@#$%^&*()-_=+[]{};:,.<>/?"


# =============================================================================
# CLI prompt and message strings
# =============================================================================
# Putting human-readable text here means we can tweak wording without
# hunting through source code, and it sets us up for future
# translation if we ever want to ship a non-English version

PROMPT_MASTER_PASSWORD: Final[str] = "Master password: "
PROMPT_MASTER_PASSWORD_NEW: Final[str] = "New master password: "
PROMPT_MASTER_PASSWORD_CONFIRM: Final[str] = "Confirm master password: "
PROMPT_ENTRY_PASSWORD: Final[str] = "Password for {entry}: "
PROMPT_ENTRY_USERNAME: Final[str] = "Username for {entry}: "
PROMPT_ENTRY_URL: Final[str] = "URL (optional, press Enter to skip): "
PROMPT_ENTRY_NOTES: Final[str] = "Notes (optional, press Enter to skip): "

MSG_VAULT_CREATED: Final[str] = "Vault created at {path}"
MSG_VAULT_ALREADY_EXISTS: Final[str] = "Vault already exists at {path}"
MSG_VAULT_NOT_FOUND: Final[str] = (
    "No vault at {path}. Run `pv init` to create one"
)
MSG_ENTRY_ADDED: Final[str] = "Added entry: {name}"
MSG_ENTRY_DELETED: Final[str] = "Deleted entry: {name}"
MSG_ENTRY_NOT_FOUND: Final[str] = "No entry named: {name}"
MSG_ENTRY_ALREADY_EXISTS: Final[str] = (
    "Entry already exists: {name}. Use --force to overwrite"
)
MSG_PASSWORDS_DO_NOT_MATCH: Final[str] = "Passwords did not match"
MSG_WRONG_MASTER_PASSWORD: Final[str] = (
    "Wrong master password (or vault file is corrupted)"
)
MSG_VAULT_EMPTY: Final[str] = "Vault is empty. Add an entry with `pv add`"

MSG_MASTER_PASSWORD_EMPTY: Final[str] = ("Master password cannot be empty")
MSG_MASTER_PASSWORD_TOO_SHORT: Final[str] = (
    "Master password must be at least {minimum} characters"
)
MSG_MASTER_PASSWORD_CHANGED: Final[str] = (
    "Master password changed. Vault re-encrypted at {path}"
)


# =============================================================================
# search / count — read-only query commands
# =============================================================================
# `pv search <substring>` filters the entry list; `pv count` prints the
# number of entries. Both are small additions on top of `list`

# Rejected when the user runs `pv search` with an empty string — an
# empty query would otherwise "match everything", defeating the point
MSG_SEARCH_EMPTY_QUERY: Final[str] = "Search query cannot be empty"
# Shown (to stderr) when no entry name contains the substring
MSG_NO_MATCHES: Final[str] = "No entries match: {query}"


# =============================================================================
# get --show — masked password display
# =============================================================================
# `pv get <name>` hides the password by default; `--show` reveals it.
# Secure-by-default: you opt IN to showing a secret on screen, never
# the other way around. The bullet string is the placeholder we print
# in place of the real password. Eight bullets carry no length
# information about the real password — important, because the length
# of a hidden secret is itself a small leak
MASKED_PASSWORD_DISPLAY: Final[str] = "••••••••"
# Fallback for terminals that cannot render the bullet glyph. We expose
# it as a constant so a future "detect terminal encoding" change has a
# single place to switch to
MASKED_PASSWORD_FALLBACK: Final[str] = "********"


# =============================================================================
# export / import — plaintext migration in and out
# =============================================================================
# These two commands move credentials across the encrypted boundary, so
# every string here leans on the side of LOUD warnings

# Default export path is the CURRENT directory, not $HOME — we want the
# user to consciously place a plaintext secrets file, not drop it
# somewhere sticky by accident
DEFAULT_EXPORT_FILENAME: Final[str] = "pv-export.json"
DEFAULT_EXPORT_PATH: Final[Path] = Path(DEFAULT_EXPORT_FILENAME)

# The schema version we stamp into export files, so a future importer
# can refuse a format it does not understand
EXPORT_FORMAT_VERSION: Final[int] = 1
EXPORT_KEY_VERSION: Final[str] = "export_version"
EXPORT_KEY_ENTRIES: Final[str] = "entries"

MSG_EXPORT_WARNING: Final[str] = (
    "WARNING: this writes EVERY password in PLAINTEXT to disk.\n"
    "Anyone who reads {path} can read all your credentials.\n"
    "Delete it the moment you are done migrating."
)
MSG_EXPORT_CONFIRM: Final[str] = "Type YES (in capitals) to export plaintext"
MSG_EXPORT_ABORTED: Final[str] = "Export aborted — nothing was written"
MSG_EXPORT_DONE: Final[str] = (
    "Exported {count} entr{plural} (PLAINTEXT) to {path}"
)
MSG_IMPORT_NOT_FOUND: Final[str] = "No import file at {path}"
MSG_IMPORT_BAD_FILE: Final[str] = "Import file is not valid: {error}"
MSG_IMPORT_DONE: Final[str] = "Imported {added} entr{plural} ({skipped} skipped)"


# =============================================================================
# init --verify — read-back check after creating a vault
# =============================================================================
MSG_VERIFY_OK: Final[str] = "Verified: the new vault unlocks with that password"
MSG_VERIFY_FAILED: Final[str] = (
    "VERIFY FAILED: the new vault did not unlock. "
    "Deleting it — nothing was kept"
)


# =============================================================================
# copy — clipboard support
# =============================================================================
MSG_COPIED: Final[str] = (
    "Password for {name} copied to clipboard "
    "(it is NOT printed here)"
)
MSG_COPY_CLEARED: Final[str] = "Clipboard cleared"
MSG_CLIPBOARD_UNAVAILABLE: Final[str] = (
    "No clipboard available. On Linux install xclip or wl-clipboard; "
    "over SSH the clipboard usually will not work"
)
# Default seconds before `pv copy --clear-after` wipes the clipboard.
# 0 means "do not auto-clear". Clipboard contents persist until
# something overwrites them, so clearing is a real security win
DEFAULT_CLIPBOARD_CLEAR_SECONDS: Final[int] = 0


# =============================================================================
# TOTP — time-based one-time passwords (RFC 6238)
# =============================================================================
# A TOTP secret is at least as sensitive as a password, so it lives
# INSIDE the encrypted vault as a field on Entry — never in a sidecar

# Six digits and a 30-second window are the near-universal defaults
# used by Google Authenticator, Authy, and almost every website
TOTP_DIGITS: Final[int] = 6
TOTP_PERIOD_SECONDS: Final[int] = 30

MSG_TOTP_NOT_CONFIGURED: Final[str] = (
    "Entry {name} has no TOTP secret. Add one with `pv add --force` "
    "or edit the entry"
)
MSG_TOTP_INVALID_SECRET: Final[str] = (
    "TOTP secret for {name} is not valid base32: {error}"
)
PROMPT_ENTRY_TOTP: Final[str] = (
    "TOTP secret (base32, optional, press Enter to skip): "
)


# =============================================================================
# backup / restore — versioned encrypted snapshots
# =============================================================================
# Backups are full copies of the ENCRYPTED vault file. They are exactly
# as safe (or unsafe) as the live vault — no more, no less

DEFAULT_BACKUP_DIRECTORY: Final[Path] = DEFAULT_VAULT_DIRECTORY / "backups"
# strftime pattern for snapshot filenames. The sortable YYYY-MM-DD
# layout means a plain alphabetical sort is also a chronological sort
BACKUP_FILENAME_FORMAT: Final[str] = "vault-%Y-%m-%d-%H%M%S.json"
BACKUP_FILENAME_GLOB: Final[str] = "vault-*.json"
# How many snapshots to keep. Older ones are pruned after each backup
DEFAULT_MAX_BACKUPS: Final[int] = 10

MSG_BACKUP_DONE: Final[str] = "Backup written to {path}"
MSG_BACKUP_PRUNED: Final[str] = "Pruned {count} old backup{plural}"
MSG_NO_BACKUPS: Final[str] = "No backups found in {path}"
MSG_BACKUP_NOT_FOUND: Final[str] = "No backup matching {ref} in {path}"
MSG_RESTORE_DONE: Final[str] = "Restored {src} onto {dst}"
MSG_RESTORE_CONFIRM: Final[str] = (
    "This OVERWRITES the live vault at {dst}. Continue?"
)


# =============================================================================
# password strength scoring (`pv add`)
# =============================================================================
# A 0-4 score, mapped to a human label and a rich color. The scale
# matches zxcvbn's 0-4 output so the optional zxcvbn backend and the
# built-in fallback estimator speak the same language
STRENGTH_LABELS: Final[dict[int, str]] = {
    0: "very weak",
    1: "weak",
    2: "fair",
    3: "strong",
    4: "excellent",
}
STRENGTH_COLORS: Final[dict[int, str]] = {
    0: "red",
    1: "red",
    2: "yellow",
    3: "green",
    4: "bright_green",
}
# At or below this score we ask the user to confirm before saving.
# We WARN, we do not BLOCK — the user may have a good reason
STRENGTH_WARN_AT_OR_BELOW: Final[int] = 1


# =============================================================================
# KDF auto-upgrade (`pv` transparently strengthens old vaults)
# =============================================================================
MSG_KDF_UPGRADING: Final[str] = (
    "Vault was created with weaker key-derivation settings. "
    "Upgrading to current defaults (this adds one ~0.5s pause)..."
)
MSG_KDF_UPGRADED: Final[str] = "Vault parameters upgraded to current defaults"

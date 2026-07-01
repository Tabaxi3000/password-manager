```ruby
██████╗  █████╗ ███████╗███████╗    ██╗   ██╗ █████╗ ██╗   ██╗██╗     ████████╗
██╔══██╗██╔══██╗██╔════╝██╔════╝    ██║   ██║██╔══██╗██║   ██║██║     ╚══██╔══╝
██████╔╝███████║███████╗███████╗    ██║   ██║███████║██║   ██║██║        ██║
██╔═══╝ ██╔══██║╚════██║╚════██║    ╚██╗ ██╔╝██╔══██║██║   ██║██║        ██║
██║     ██║  ██║███████║███████║     ╚████╔╝ ██║  ██║╚██████╔╝███████╗   ██║
╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝      ╚═══╝  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝
```

> Encrypted command-line password manager — Argon2id key derivation, AES-256-GCM authenticated encryption, atomic durable writes, advisory file locking. One master password protects every credential you trust to it.

## What It Does

- Stores credentials in a single encrypted JSON file at `~/.password-vault/vault.json` (mode `0600`)
- Derives a 32-byte AES key from your master password via **Argon2id** (OWASP-recommended parameters, ~0.5s per derivation)
- Encrypts vault contents with **AES-256-GCM** — confidentiality + tamper detection in one primitive
- **Atomic, durable, concurrent-safe** writes: tmp file → fsync → atomic rename → directory fsync, with advisory `fcntl` lock to serialize concurrent `pv` invocations
- Master password rotation that re-encrypts the entire vault under a fresh salt and key
- Cryptographically secure password generator using `secrets` (never `random`) with a Fisher-Yates shuffle on top of `secrets.randbelow`
- Stores KDF parameters *in the file* — old vaults remain readable when defaults change, and rotation can upgrade them transparently
- Typed exception hierarchy (`WrongPasswordError`, `VaultFormatError`, `EntryNotFoundError`, …) for precise error handling
- Rich-rendered colored panels and tables; pipe-friendly stdout/stderr separation
- Refuses to distinguish "wrong password" from "tampered file" — both look the same cryptographically, exposing the difference helps attackers

## Quick Start

```bash
./install.sh
just run -- init
just run -- add github
just run -- get github
```

```text
$ pv init
New master password: ************
Confirm master password: ************
Vault created at /home/you/.password-vault/vault.json

$ pv add github
Username for github: alice
Password for github (hidden): ************
URL (optional, press Enter to skip): https://github.com
Notes (optional, press Enter to skip):
Added entry: github

$ pv get github
╭────────────────── github ──────────────────╮
│ username   alice                           │
│ password   hunter2-but-better              │
│ url        https://github.com              │
│ created    2026-05-13T14:22:10+00:00       │
│ updated    2026-05-13T14:22:10+00:00       │
╰────────────────────────────────────────────╯
```

> [!TIP]
> This project uses [`just`](https://github.com/casey/just) as a command runner. Type `just` to see all available recipes.
>
> Install: `curl -sSf https://just.systems/install.sh | bash -s -- --to ~/.local/bin`

## Commands

| Command | What it does |
|---------|--------------|
| `pv init` | Create a new empty vault. Prompts for the master password twice. |
| `pv add <name>` | Add an entry. Prompts for username, password, optional URL and notes. `--generate` / `-g` to use a random password. |
| `pv get <name>` | Show every field of one entry in a colored panel. |
| `pv list` | Print every entry name as a table (no passwords shown). |
| `pv delete <name>` | Remove an entry by name. |
| `pv gen [length]` | Generate a strong random password and print it to stdout. No vault required. |
| `pv change-password` | Rotate the master password — re-encrypts the entire vault under a fresh salt and key. |

Every command takes `--vault PATH` (or `$PV_VAULT`) to point at an alternate vault file.

## Demo: pipe-friendly generation

```bash
# Generate and copy to clipboard (macOS)
just run -- gen 32 | pbcopy

# Generate and copy to clipboard (Linux)
just run -- gen 32 | xclip -selection clipboard

# Generate into a shell variable
PASSWORD=$(just run -- gen 32)

# Letters + digits only, no symbols
just run -- gen 24 --no-symbols
```

> [!IMPORTANT]
> `pv` *never* accepts the master password as a CLI flag. Passwords passed as flags leak into shell history (`history` command) and process listings (`ps aux`). Every prompt uses `getpass.getpass()` — same primitive `sudo` uses — so the password is never echoed and never logged.

## Cryptographic guarantees

| Concern | Mitigation |
|---------|-----------|
| Vault file stolen | Argon2id with 64 MiB / 3 passes / 4 lanes makes each guess ~0.5s; a billion guesses ≈ 15 years |
| Vault file tampered | AES-GCM authentication tag refuses to decrypt; same error as "wrong password" by design |
| Power loss mid-save | Atomic write: tmp → fsync → `os.replace` → parent-dir fsync. Always old-or-new, never half |
| Two `pv` processes racing | Advisory `fcntl.LOCK_EX` on sidecar `.lock` file (POSIX; NTFS atomic-rename on Windows) |
| Vault tmp world-readable | `os.open` with mode `0o600` at the very first syscall — no chmod race window |
| Predictable random output | `secrets` module everywhere — for salts, nonces, passwords, and the Fisher-Yates shuffle |
| Aging KDF parameters | Parameters stored in the vault file; `change-password` can upgrade them transparently |
| KDF parameter corruption | Validated against Argon2's algorithmic floors on load; clean `VaultFormatError` instead of library crash |
| Forward-incompatible format | Top-level `version` field; future versions can refuse or migrate |

## Tooling

```bash
just            # list available recipes
just test       # run pytest (60+ tests across crypto, vault, generator)
just test-cov   # tests + coverage report
just lint       # ruff + mypy + pylint
just format     # yapf
just run -- <cmd> [args]
```

## Requirements

- **Python 3.13+** — the install script will check.
- [`uv`](https://github.com/astral-sh/uv) — modern Python package manager (auto-installed by `./install.sh`).
- [`just`](https://github.com/casey/just) — command runner (auto-installed by `./install.sh`).
- Linux, macOS, or WSL2 strongly recommended over native Windows — file locking and directory `fsync` paths are POSIX-flavored. NTFS gives atomic `os.replace` regardless, so native Windows works with reduced concurrency guarantees.

No compilers or system libraries beyond what `argon2-cffi` and `cryptography` install through `uv`. No network access required at runtime.
"""
clipboard.py

Putting a password on the system clipboard without printing it

────────────────────────────────────────────────────────────────────
Why a whole file for "copy to clipboard"
────────────────────────────────────────────────────────────────────
There is no single cross-platform clipboard in Python's standard
library, and every operating system exposes the clipboard differently:

  macOS    — `pbcopy` / `pbpaste` (always installed)
  Windows  — `clip` (always installed)
  Linux    — `wl-copy` (Wayland) or `xclip` / `xsel` (X11), and you
             have to INSTALL one of them; a bare Linux box has none
  SSH      — usually nothing works, because there is no local display

The `pyperclip` library papers over most of this, so we use it when it
is installed. When it is NOT, we fall back to shelling out to whichever
native command exists. Either way, if there is genuinely no clipboard
available (common over SSH), we raise a clear error instead of failing
mysteriously

────────────────────────────────────────────────────────────────────
The security trade-off
────────────────────────────────────────────────────────────────────
The clipboard is shared, global, and sticky: every app can read it,
and it holds your password until something else overwrites it. That is
why `pv copy` exists (so the password never hits your terminal
scrollback or shell history) AND why the CLI offers to clear the
clipboard after a delay. Copying a secret is safer than printing it,
but it is not free

What this module exposes
  copy(text)      — put text on the clipboard (raises ClipboardError)
  clear()         — overwrite the clipboard with an empty string
  ClipboardError  — no working clipboard mechanism was found

Connects to
  main.py — the `pv copy <name>` command calls copy()/clear()
"""

# Standard library: `contextlib.suppress` to swallow a "no clipboard"
# error during best-effort cleanup in one line.
import contextlib
# Standard library: run the native clipboard helper (pbcopy, clip,
# wl-copy, xclip) as a subprocess when pyperclip is unavailable.
import shutil
import subprocess
import sys


class ClipboardError(Exception):
    """
    Raised when no working clipboard mechanism is available

    The CLI turns this into a friendly "install xclip / clipboard does
    not work over SSH" message rather than a traceback
    """


# Native command pipelines per platform, tried in order. Each entry is
# the argv list we feed the secret to on stdin. We pick the first whose
# executable actually exists on PATH
def _native_copy_commands() -> list[list[str]]:
    """
    Return candidate "write stdin to clipboard" commands for this OS

    Ordered by preference. Only commands whose binary is present on
    PATH are worth trying; the caller filters with shutil.which
    """
    if sys.platform == "darwin":
        return [["pbcopy"]]
    if sys.platform == "win32":
        return [["clip"]]
    # Assume Linux/BSD: prefer Wayland, then X11 helpers
    return [
        ["wl-copy"],
        ["xclip", "-selection", "clipboard"],
        ["xsel", "--clipboard", "--input"],
    ]


def _copy_via_native(text: str) -> bool:
    """
    Try to copy using a native OS command. Return True on success

    Returns False if no candidate command exists on PATH, so the caller
    knows to raise ClipboardError. Re-raises nothing on a found-but-
    failed command except as a False, keeping the contract simple
    """
    for argv in _native_copy_commands():
        if shutil.which(argv[0]) is None:
            continue
        try:
            subprocess.run(
                argv,
                input = text.encode("utf-8"),
                check = True,
            )
            return True
        except (subprocess.SubprocessError, OSError):
            # This helper exists but failed (no display, etc.). Try the
            # next candidate rather than giving up immediately
            continue
    return False


def copy(text: str) -> None:
    """
    Place `text` on the system clipboard

    Prefers pyperclip (handles the platform quirks for us); falls back
    to a native command. Raises ClipboardError if neither works — which
    is the honest answer over SSH or on a bare Linux box with no
    clipboard tool installed
    """
    # Lazy import: pyperclip is an OPTIONAL dependency. Importing it at
    # module load would crash `pv` for anyone who skipped the extra, so
    # we only reach for it here, inside the function
    try:
        import pyperclip
        try:
            pyperclip.copy(text)
            return
        except pyperclip.PyperclipException:
            # pyperclip is installed but found no backend — fall through
            # to our own native attempt before giving up
            pass
    except ImportError:
        pass

    if not _copy_via_native(text):
        raise ClipboardError("no working clipboard mechanism found")


def clear() -> None:
    """
    Best-effort wipe of the clipboard by overwriting it with ""

    Used by `pv copy --clear-after`. Swallows ClipboardError: if there
    was no clipboard we could write to, there is nothing to clear, and
    failing the whole command on cleanup would be worse than the leak
    """
    with contextlib.suppress(ClipboardError):
        copy("")

"""
totp.py

Time-based one-time passwords (the 6-digit 2FA codes), from scratch

────────────────────────────────────────────────────────────────────
What a TOTP actually is
────────────────────────────────────────────────────────────────────
When a website shows you a QR code for "two-factor authentication"
and you scan it into Google Authenticator, all that QR code contains
is a shared secret — a random string, usually written in base32. From
then on, BOTH your phone and the website know that secret, and BOTH
compute the same 6-digit code from it using nothing but the current
time. No network, no sync. That is the whole trick

The algorithm is RFC 6238, and it is short enough to write by hand:

  1. Take the current Unix time and divide by 30 (the time "step").
     This counter changes once every 30 seconds. Both sides compute
     the same counter because both sides agree on the clock
  2. HMAC-SHA1 the 8-byte counter using the shared secret as the key
  3. "Dynamically truncate" the 20-byte HMAC down to a 31-bit number
     (the last nibble of the HMAC tells you WHERE to slice)
  4. Take that number modulo 1_000_000 → a 6-digit code

The `pyotp` library does this in two lines, but the point of this file
is that you can SEE the whole thing. It is ~30 lines of real logic
wrapped in comments

────────────────────────────────────────────────────────────────────
Why this lives inside the vault
────────────────────────────────────────────────────────────────────
The TOTP secret is at LEAST as sensitive as the password — anyone who
has it can generate your 2FA codes forever. So it is stored as a field
on Entry, inside the encrypted vault, never in a sidecar file

What this module exposes
  generate_totp(secret) — the current 6-digit code for a base32 secret
  seconds_remaining()   — how long until the current code rolls over
  TotpError             — raised when the secret is not valid base32

Connects to
  main.py — the `pv totp <name>` command calls these
  constants.py — pulls the digit count and time-step from here
"""

# Standard library: base32 decode — the format websites hand out TOTP
# secrets in (A-Z and 2-7, no padding usually).
import base64
# Standard library: keyed-hash message authentication. TOTP is built
# on HMAC-SHA1 of the time counter.
import hmac
# Standard library: the SHA1 hash function HMAC needs. SHA1 is broken
# for collision resistance but fine here — RFC 6238 mandates it and
# HMAC does not rely on collision resistance.
import hashlib
# Standard library: pack the time counter into 8 big-endian bytes,
# exactly as the RFC specifies.
import struct
# Standard library: the current wall-clock time, in seconds since the
# Unix epoch. Both phone and server use this same clock.
import time

# Local: the universal defaults (6 digits, 30-second window) live in
# constants so the rest of the codebase stays self-documenting.
from password_manager.constants import (
    TOTP_DIGITS,
    TOTP_PERIOD_SECONDS,
)


class TotpError(ValueError):
    """
    Raised when a TOTP secret cannot be decoded as base32

    Subclasses ValueError so callers that only care "this input was
    bad" can catch the broader type
    """


def _decode_base32_secret(secret: str) -> bytes:
    """
    Turn a base32 TOTP secret string into the raw key bytes

    Real-world secrets arrive messy: lowercase, with spaces every four
    characters (the way authenticator apps display them), and usually
    WITHOUT the trailing `=` padding base64.b32decode insists on. We
    normalize all of that before decoding

    Raises TotpError if the result is not valid base32
    """
    # Strip the spaces apps add for readability, then uppercase —
    # base32's alphabet is uppercase A-Z and digits 2-7
    cleaned = secret.replace(" ", "").upper()
    if not cleaned:
        raise TotpError("TOTP secret is empty")

    # base64.b32decode requires the input length to be a multiple of 8,
    # padded with '='. Authenticator secrets almost never include the
    # padding, so we add it back here
    remainder = len(cleaned) % 8
    if remainder:
        cleaned += "=" * (8 - remainder)

    try:
        return base64.b32decode(cleaned, casefold = True)
    except (ValueError, TypeError) as exc:
        raise TotpError(f"not valid base32: {exc}") from exc


def generate_totp(
    secret: str,
    *,
    digits: int = TOTP_DIGITS,
    period: int = TOTP_PERIOD_SECONDS,
    at: float | None = None,
) -> str:
    """
    Compute the current TOTP code for a base32 secret

    Parameters
    ----------
    secret
        The base32 shared secret, exactly as the website gave it to you
        (spaces and lowercase are tolerated)
    digits
        How many digits in the code. 6 is near-universal
    period
        The time step in seconds. 30 is near-universal
    at
        Unix timestamp to compute the code "at". Defaults to now. Exists
        so tests can pin a specific time and assert a known code — the
        RFC even ships official test vectors keyed to specific times

    Returns
    -------
    str
        The code, zero-padded to `digits` characters (e.g. "004321")

    Raises
    ------
    TotpError
        If the secret is not valid base32
    """
    key = _decode_base32_secret(secret)

    # Which 30-second window are we in? Integer division of the Unix
    # time by the period. This is the value both sides must agree on
    now = time.time() if at is None else at
    counter = int(now // period)

    # RFC 6238 / 4226: the counter is the HMAC *message*, packed as an
    # 8-byte big-endian unsigned integer. ">Q" = big-endian uint64
    counter_bytes = struct.pack(">Q", counter)
    mac = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # "Dynamic truncation." The low 4 bits of the last byte give an
    # offset 0-15; we read the 4 bytes starting there, mask off the top
    # bit (to dodge signed-vs-unsigned ambiguity), and get a 31-bit int
    offset = mac[-1] & 0x0F
    truncated = struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFF_FFFF

    # Reduce to the requested number of digits and zero-pad. A code of
    # 4321 must display as "004321", or it is the wrong code
    code = truncated % (10 ** digits)
    return str(code).zfill(digits)


def seconds_remaining(
    *,
    period: int = TOTP_PERIOD_SECONDS,
    at: float | None = None,
) -> int:
    """
    Return how many seconds the current code stays valid

    The CLI prints this so the user does not grab a code that is about
    to roll over mid-login. If we are 12 seconds into a 30-second
    window, 18 seconds remain
    """
    now = time.time() if at is None else at
    return period - int(now % period)

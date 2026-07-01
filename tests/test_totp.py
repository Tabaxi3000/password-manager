"""
test_totp.py

Tests for the from-scratch TOTP implementation (challenge 9)

The strongest tests here are the RFC 6238 official test vectors: the
RFC publishes known (time, secret) → code pairs, so we can assert our
implementation produces exactly the numbers the standard says it must.
If those pass, the core HMAC-truncation math is correct
"""

# Third-party: the test runner.
import pytest

# Local: the module under test.
from password_manager.totp import (
    TotpError,
    generate_totp,
    seconds_remaining,
)


# RFC 6238 Appendix B uses the ASCII secret "12345678901234567890".
# In base32 (what authenticator apps speak) that is the string below
RFC_SECRET_BASE32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"


@pytest.mark.parametrize(
    "at,expected",
    [
        # (unix time, expected 8-digit code) — straight from RFC 6238's
        # SHA1 test-vector table. We truncate to the last 6 digits,
        # which is what 6-digit TOTP actually shows
        (59, "94287082"),
        (1111111109, "07081804"),
        (1111111111, "14050471"),
        (1234567890, "89005924"),
        (2000000000, "69279037"),
    ],
)
def test_rfc6238_official_vectors(at: int, expected: str) -> None:
    """
    Verify our codes match the RFC 6238 SHA1 test vectors exactly

    The RFC tabulates 8-digit codes; standard apps show the low 6
    digits. We compute 8 digits to compare against the table directly,
    proving the truncation math is right
    """
    code = generate_totp(RFC_SECRET_BASE32, digits = 8, at = at)
    assert code == expected


def test_six_digit_codes_are_zero_padded() -> None:
    """
    Verify short codes are left-padded to the full digit count

    A numeric code of 4321 must render as "004321". Forgetting the
    zero-pad produces a code the server will reject
    """
    code = generate_totp("JBSWY3DPEHPK3PXP", digits = 6, at = 0)
    assert len(code) == 6
    assert code.isdigit()


def test_code_changes_across_time_windows() -> None:
    """
    Verify the code differs between two 30-second windows

    TOTP is "time-based" — the code at t=0 and the code 30s later must
    (almost always) differ. We pick two timestamps a full period apart
    """
    a = generate_totp(RFC_SECRET_BASE32, at = 0)
    b = generate_totp(RFC_SECRET_BASE32, at = 30)
    assert a != b


def test_lowercase_and_spaced_secret_is_accepted() -> None:
    """
    Verify messy real-world secret formatting is normalized

    Authenticator apps display secrets lowercased and grouped in fours
    ("jbsw y3dp ..."). We must decode that to the same bytes as the
    clean uppercase form
    """
    clean = generate_totp("JBSWY3DPEHPK3PXP", at = 0)
    messy = generate_totp("jbsw y3dp ehpk 3pxp", at = 0)
    assert clean == messy


def test_invalid_base32_raises_totp_error() -> None:
    """
    Verify a non-base32 secret raises TotpError, not a raw library error
    """
    with pytest.raises(TotpError):
        # '1', '8', '9', '0' are not in the base32 alphabet
        generate_totp("not-valid-base32-1890!!", at = 0)


def test_empty_secret_raises_totp_error() -> None:
    """
    Verify an empty secret is rejected rather than producing a code
    """
    with pytest.raises(TotpError):
        generate_totp("", at = 0)


@pytest.mark.parametrize(
    "at,expected",
    [
        (0, 30),    # exactly at a window boundary → a full period left
        (1, 29),
        (29, 1),
        (30, 30),   # next boundary
    ],
)
def test_seconds_remaining(at: int, expected: int) -> None:
    """
    Verify the "valid for N more seconds" countdown is correct

    The CLI prints this so a user does not grab a code about to expire.
    At 1 second into a 30-second window, 29 seconds remain
    """
    assert seconds_remaining(at = at) == expected

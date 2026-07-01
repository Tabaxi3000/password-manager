"""
strength.py

Scoring how strong a password is, on the 0-4 scale users recognize

────────────────────────────────────────────────────────────────────
"Looks random" vs "would survive an attack"
────────────────────────────────────────────────────────────────────
A human glancing at "Summer2024!" sees uppercase, lowercase, a digit,
a symbol, and calls it strong. An offline cracking rig sees a
dictionary word, a year, and a "!" — three of the most predictable
patterns there are — and breaks it in seconds. The gap between those
two judgments is exactly what a real strength estimator measures

The gold standard is Dropbox's `zxcvbn`, which knows about dictionary
words, keyboard walks ("qwerty"), dates, and l33t-speak substitutions.
If it is installed we use it. If it is NOT installed we fall back to a
simpler entropy estimate so the feature still works — it is less smart
(it cannot tell "password123" is weak) but it still rewards length and
variety, which is most of the battle

────────────────────────────────────────────────────────────────────
The 0-4 scale
────────────────────────────────────────────────────────────────────
Both backends report a score from 0 (trivially guessable) to 4
(excellent). We map that number to a human label and a rich color in
constants.py. The caller WARNS on a low score but never BLOCKS the
save — the user may have a reason we do not know about

What this module exposes
  score_password(password) — (score 0-4, label, color)

Connects to
  main.py — the `pv add` command scores the entered password
  constants.py — pulls the label/color maps from here
"""

# Standard library: log base 2, for the entropy = length * log2(pool)
# estimate the fallback scorer uses.
import math

# Local: the character pools (to measure which classes a password
# draws from) plus the label/color maps for the 0-4 scale.
from password_manager.constants import (
    DIGITS,
    LOWERCASE_LETTERS,
    SAFE_SYMBOLS,
    STRENGTH_COLORS,
    STRENGTH_LABELS,
    UPPERCASE_LETTERS,
)


def score_password(password: str) -> tuple[int, str, str]:
    """
    Score a password and return (score, label, color)

    score is 0-4 (0 worst, 4 best). label is a word like "strong".
    color is a rich color name like "green", ready to drop into markup

    Uses zxcvbn if it is installed; otherwise a built-in entropy
    estimate. Either way the 0-4 scale and the returned label/color are
    identical, so the rest of the program does not care which ran
    """
    score = _zxcvbn_score(password)
    if score is None:
        score = _fallback_score(password)
    # Clamp defensively so a backend that ever returns out-of-range
    # cannot KeyError the label/color lookup
    score = max(0, min(4, score))
    return score, STRENGTH_LABELS[score], STRENGTH_COLORS[score]


def _zxcvbn_score(password: str) -> int | None:
    """
    Return zxcvbn's 0-4 score, or None if zxcvbn is not installed

    The import lives INSIDE the function on purpose: zxcvbn is an
    optional dependency, so importing it at module load would crash
    `pv` for everyone who did not install the extra. Importing lazily
    means the cost (and the possible ImportError) only happens when we
    actually try to score a password
    """
    try:
        from zxcvbn import zxcvbn
    except ImportError:
        return None
    # zxcvbn raises on an empty string; treat that as the worst score
    if not password:
        return 0
    result = zxcvbn(password)
    return int(result["score"])


def _fallback_score(password: str) -> int:
    """
    Estimate strength from length and character variety, no library

    This is deliberately simple: count how big the character pool is
    (lowercase adds 26, digits add 10, and so on), estimate the entropy
    as length * log2(pool_size), and bucket the result into 0-4 using
    thresholds borrowed from common password-strength guidance

    It cannot spot dictionary words or "qwerty" — that is what zxcvbn is
    for — but it correctly rewards "longer and more varied" over "short
    and one-class", which catches the most common weak passwords
    """
    if not password:
        return 0

    # Size of the alphabet an attacker would have to brute-force,
    # inferred from which character classes actually appear
    pool = 0
    if any(c in LOWERCASE_LETTERS for c in password):
        pool += len(LOWERCASE_LETTERS)
    if any(c in UPPERCASE_LETTERS for c in password):
        pool += len(UPPERCASE_LETTERS)
    if any(c in DIGITS for c in password):
        pool += len(DIGITS)
    if any(c in SAFE_SYMBOLS for c in password):
        pool += len(SAFE_SYMBOLS)
    # Anything outside our known pools (spaces, unicode) — give it a
    # modest fixed credit rather than ignoring it
    if any(
        c not in LOWERCASE_LETTERS + UPPERCASE_LETTERS + DIGITS + SAFE_SYMBOLS
        for c in password
    ):
        pool += 10

    # Entropy in bits ≈ how many bits an ideal random password of this
    # length over this pool would carry. Real passwords carry less
    # (people are not random), so these thresholds stay conservative
    entropy = len(password) * math.log2(pool) if pool else 0.0

    if entropy < 28:
        return 0
    if entropy < 40:
        return 1
    if entropy < 60:
        return 2
    if entropy < 90:
        return 3
    return 4

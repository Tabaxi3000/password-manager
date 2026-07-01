"""
test_strength.py

Tests for password strength scoring (challenge 6)

score_password uses zxcvbn when it is installed and a built-in entropy
estimate otherwise. These tests assert on properties that hold for
BOTH backends (a long, varied password beats a short one) plus a few
that pin the fallback estimator directly, so the suite is meaningful
whether or not the optional zxcvbn extra is present
"""

# Local: the public scorer and the private fallback we test in isolation.
from password_manager.constants import (
    STRENGTH_COLORS,
    STRENGTH_LABELS,
)
from password_manager.strength import (
    _fallback_score,
    score_password,
)


# =============================================================================
# Public score_password — backend-agnostic properties
# =============================================================================


def test_score_password_returns_valid_triple() -> None:
    """
    Verify score_password returns (score 0-4, matching label, matching color)

    Whichever backend runs, the score must be in range and the label and
    color must be the ones constants.py maps that score to
    """
    score, label, color = score_password("anything-at-all")
    assert 0 <= score <= 4
    assert label == STRENGTH_LABELS[score]
    assert color == STRENGTH_COLORS[score]


def test_short_password_scores_low() -> None:
    """
    Verify a tiny password scores at the weak end (<= 1)

    True for zxcvbn (dictionary/short) and for the entropy fallback
    (low length × small pool). "a" should never be called strong
    """
    score, _, _ = score_password("a")
    assert score <= 1


def test_long_varied_password_scores_high() -> None:
    """
    Verify a long, mixed-class, non-dictionary password scores high (>= 3)

    Holds for both backends: lots of entropy, no obvious pattern
    """
    score, _, _ = score_password("7xQ!9pL@2vR#4nT^8wZ&3kM")
    assert score >= 3


def test_empty_password_scores_zero() -> None:
    """
    Verify an empty password is the worst possible score
    """
    score, _, _ = score_password("")
    assert score == 0


# =============================================================================
# Fallback estimator — exercised directly (no zxcvbn needed)
# =============================================================================


def test_fallback_score_bounds() -> None:
    """
    Verify the fallback estimator never leaves the 0-4 range
    """
    for sample in ["", "a", "abc123", "CorrectHorseBatteryStaple", "!" * 40]:
        assert 0 <= _fallback_score(sample) <= 4


def test_fallback_rewards_length_and_variety() -> None:
    """
    Verify the fallback rates a longer, more varied password higher

    The estimator is simple, but it must get the basic ordering right:
    more length and more character classes → a higher score
    """
    weak = _fallback_score("aaaa")
    strong = _fallback_score("aB3$xY9!aB3$xY9!")
    assert strong > weak

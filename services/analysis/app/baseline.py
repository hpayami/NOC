"""Robust statistical baseline scoring (advisory only).

A per-feature baseline is the median and MAD of the feature's recent history. The current value
is scored by its robust z-score; scores are squashed into [0, 1]. No training step, no learned
parameters, no external calls — and therefore no claim beyond "this value is unusual relative to
this subject's own recent history". Results never trigger enforcement.
"""

from __future__ import annotations

import math
from dataclasses import dataclass

MODEL_NAME = "robust-baseline"
MODEL_VERSION = "1.0.0"
MIN_HISTORY_POINTS = 12
# |z| at which the squashed score reaches ~0.5; chosen for hourly network counts, documented, fixed.
Z_MIDPOINT = 4.0
MAD_SCALE = 1.4826  # MAD → sigma for a normal distribution


@dataclass(frozen=True)
class FeatureScore:
    feature: str
    current: float
    median: float
    mad: float
    z: float
    contribution: float


class InsufficientHistory(ValueError):
    def __init__(self, feature: str, points: int) -> None:
        super().__init__(f"feature {feature!r} has {points} history points; {MIN_HISTORY_POINTS} required")
        self.feature = feature
        self.points = points


def _median(values: list[float]) -> float:
    s = sorted(values)
    n = len(s)
    mid = n // 2
    return s[mid] if n % 2 else (s[mid - 1] + s[mid]) / 2


def robust_z(history: list[float], current: float) -> tuple[float, float, float]:
    """Returns (median, mad, z). A zero MAD falls back to a small floor so a flat history
    still yields a finite, large z for any deviation."""
    med = _median(history)
    mad = _median([abs(v - med) for v in history]) * MAD_SCALE
    floor = max(1.0, abs(med) * 0.05)
    sigma = mad if mad > 0 else floor
    return med, mad, (current - med) / sigma


def squash(z: float) -> float:
    """Monotonic map of |z| into [0, 1): 0.5 at Z_MIDPOINT, approaching 1 for extreme values."""
    a = abs(z)
    return a / (a + Z_MIDPOINT)


def score_features(features: dict[str, tuple[list[float], float]]) -> tuple[float, list[FeatureScore]]:
    """features: name -> (history, current). Score is the maximum feature score; contributions
    are the per-feature scores normalised to sum to 1 so an explanation always adds up."""
    if not features:
        raise ValueError("no features supplied")
    scored: list[FeatureScore] = []
    for name, (history, current) in features.items():
        if len(history) < MIN_HISTORY_POINTS:
            raise InsufficientHistory(name, len(history))
        med, mad, z = robust_z(history, current)
        scored.append(FeatureScore(name, current, med, mad, z, squash(z)))
    total = sum(f.contribution for f in scored)
    if total > 0:
        scored = [
            FeatureScore(f.feature, f.current, f.median, f.mad, f.z, f.contribution / total) for f in scored
        ]
    else:
        share = 1.0 / len(scored)
        scored = [FeatureScore(f.feature, f.current, f.median, f.mad, f.z, share) for f in scored]
    score = max(squash(f.z) for f in scored)
    if math.isnan(score):
        raise ValueError("score is not a number")
    return round(score, 4), scored

"""Randomness sources for the Laplace mechanism.

Formal releases draw from :class:`SystemNoise`, which is backed by the
operating system CSPRNG (``secrets``) and can never be seeded by a caller.
Tests inject :class:`DeterministicNoise` so that sensitivity, budget
accounting and retry behaviour can be checked against fixed draws.  The
service dispatch layer never accepts a seed or random source from a request.
"""
import math
import random
import secrets


class NoiseError(Exception):
    pass


def laplace_inverse_cdf(uniform, scale):
    """Inverse CDF of Laplace(0, scale) for a uniform draw in (0, 1)."""
    if scale <= 0 or not math.isfinite(scale):
        raise NoiseError('Laplace scale must be a finite positive number')
    if not 0.0 < uniform < 1.0:
        raise NoiseError('Uniform draw must lie strictly inside the unit interval')
    if uniform < 0.5:
        return scale * math.log(2.0 * uniform)
    return -scale * math.log(2.0 * (1.0 - uniform))


class NoiseSource:
    """Abstract randomness source: every draw is a Laplace sample."""

    def laplace(self, scale):
        raise NotImplementedError

    def laplace_vector(self, scales):
        return [self.laplace(scale) for scale in scales]


class SystemNoise(NoiseSource):
    """Production randomness.  The stream cannot be fixed by callers."""

    def __init__(self):
        self._generator = secrets.SystemRandom()

    def laplace(self, scale):
        uniform = self._generator.random()
        if uniform == 0.0:  # SystemRandom.random can in principle return 0.0
            uniform = 1e-17
        return laplace_inverse_cdf(uniform, scale)


class DeterministicNoise(NoiseSource):
    """Seeded test-only randomness.  Never wired into formal release paths."""

    def __init__(self, seed):
        if not isinstance(seed, int) or not 0 <= seed <= 2**63 - 1:
            raise NoiseError('Deterministic seed must be a bounded integer')
        self.seed = seed
        self._generator = random.Random(seed)
        self.draws = 0

    def laplace(self, scale):
        uniform = self._generator.random()
        if uniform == 0.0:
            uniform = 1e-17
        self.draws += 1
        return laplace_inverse_cdf(uniform, scale)

    def reset(self):
        self._generator = random.Random(self.seed)
        self.draws = 0

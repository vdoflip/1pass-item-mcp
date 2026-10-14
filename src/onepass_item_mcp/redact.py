"""Best-effort masking of secret values (and common encodings of them) in command output.

Masking is a second line of defense. The first is that only allowlisted commands,
which can't evaluate code, ever receive the secret.
"""

from __future__ import annotations

import base64
import json
import urllib.parse
from collections.abc import Callable
from dataclasses import dataclass, field

MIN_SECRET_LENGTH = 4
MIN_FRAGMENT_LENGTH = 8


class SecretTooShortError(ValueError):
    """The secret is too short to be masked without destroying unrelated output."""


def _b64_cores(raw: bytes, encode: Callable[[bytes], bytes]) -> set[str]:
    """Base64 substrings that appear whenever `raw` is encoded at any byte alignment."""
    out: set[str] = set()
    for offset in range(3):
        encoded = encode(b"\0" * offset + raw).decode("ascii")
        start = (offset * 4 + 2) // 3  # chars influenced by the padding prefix
        end_trim = 3  # last group may mix with following bytes / padding
        core = encoded[start : len(encoded) - end_trim]
        if len(core) >= MIN_FRAGMENT_LENGTH:
            out.add(core)
    return out


def secret_variants(secret: str) -> set[str]:
    """The literal secret plus encodings an output might contain."""
    if len(secret) < MIN_SECRET_LENGTH:
        raise SecretTooShortError(
            f"secret shorter than {MIN_SECRET_LENGTH} characters cannot be masked safely"
        )
    raw = secret.encode("utf-8")
    variants = {
        secret,
        secret.strip(),
        secret[::-1],
        urllib.parse.quote(secret, safe=""),
        urllib.parse.quote_plus(secret, safe=""),
        json.dumps(secret)[1:-1],
        raw.hex(),
        raw.hex().upper(),
    }
    variants |= _b64_cores(raw, base64.b64encode)
    variants |= _b64_cores(raw, base64.urlsafe_b64encode)
    # Multi-line secrets (keys, certificates): also mask each substantial line.
    for line in secret.splitlines():
        if len(line.strip()) >= MIN_FRAGMENT_LENGTH:
            variants.add(line.strip())
    return {v for v in variants if len(v) >= MIN_SECRET_LENGTH}


@dataclass
class Redactor:
    """Replaces every known secret variant with a labelled placeholder."""

    _patterns: list[tuple[str, str]] = field(default_factory=list)

    def add(self, label: str, secret: str) -> None:
        placeholder = f"[REDACTED:{label}]"
        for v in secret_variants(secret):
            self._patterns.append((v, placeholder))
        # Longest first so a variant never leaves a partial match of a longer one.
        self._patterns.sort(key=lambda p: len(p[0]), reverse=True)

    @property
    def max_variant_length(self) -> int:
        return max((len(v) for v, _ in self._patterns), default=0)

    def redact(self, text: str) -> tuple[str, int]:
        count = 0
        for value, placeholder in self._patterns:
            n = text.count(value)
            if n:
                count += n
                text = text.replace(value, placeholder)
        return text, count

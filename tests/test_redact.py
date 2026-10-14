from __future__ import annotations

import base64
import json
import urllib.parse

import pytest

from onepass_item_mcp.redact import Redactor, SecretTooShortError, secret_variants

SECRET = "ghp_ExampleToken/With+Special=Chars"


def redact(text: str, secret: str = SECRET) -> tuple[str, int]:
    r = Redactor()
    r.add("gh", secret)
    return r.redact(text)


def test_literal() -> None:
    out, n = redact(f"token is {SECRET}.")
    assert SECRET not in out
    assert "[REDACTED:gh]" in out
    assert n == 1


def test_multiple_occurrences() -> None:
    out, n = redact(f"{SECRET}\n{SECRET}")
    assert n == 2
    assert SECRET not in out


@pytest.mark.parametrize("prefix", ["", "a", "ab", "abc", "Authorization: Basic "])
@pytest.mark.parametrize("encoder", [base64.b64encode, base64.urlsafe_b64encode])
def test_base64_at_any_alignment(prefix: str, encoder: object) -> None:
    encoded = encoder((prefix + SECRET + "trailing").encode()).decode()  # type: ignore[operator]
    out, n = redact(encoded)
    assert n >= 1
    # No long run of the encoded secret survives.
    core = encoder(SECRET.encode()).decode()[4:-4]  # type: ignore[operator]
    assert core not in out


@pytest.mark.parametrize(
    "transform",
    [
        lambda s: s.encode().hex(),
        lambda s: s.encode().hex().upper(),
        lambda s: urllib.parse.quote(s, safe=""),
        lambda s: urllib.parse.quote_plus(s, safe=""),
        lambda s: s[::-1],
        lambda s: json.dumps({"t": s}),
    ],
)
def test_common_encodings(transform: object) -> None:
    text = transform(SECRET)  # type: ignore[operator]
    _, n = redact(f"x {text} y")
    assert n >= 1


def test_multiline_secret_lines_masked() -> None:
    key = "-----BEGIN KEY-----\nAAAABBBBCCCCDDDDEEEE\nFFFFGGGGHHHHIIII\n-----END KEY-----"
    out, n = redact("second line: FFFFGGGGHHHHIIII", secret=key)
    assert "FFFFGGGGHHHHIIII" not in out
    assert n == 1


def test_unrelated_text_untouched() -> None:
    out, n = redact("nothing to see here")
    assert out == "nothing to see here"
    assert n == 0


def test_too_short_secret() -> None:
    with pytest.raises(SecretTooShortError):
        secret_variants("abc")


def test_short_variants_dropped() -> None:
    assert all(len(v) >= 4 for v in secret_variants("abcd"))


def test_multiple_secrets_labelled() -> None:
    r = Redactor()
    r.add("one", "first-secret-value")
    r.add("two", "second-secret-value")
    out, n = r.redact("first-secret-value second-secret-value")
    assert out == "[REDACTED:one] [REDACTED:two]"
    assert n == 2
    assert r.max_variant_length >= len("second-secret-value")

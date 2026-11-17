import base64
import unicodedata
from collections import Counter

from security_proxy import SecretVault, _normalize_with_mapping, scan_and_sanitize


def _fake_openai_key():
    return "sk-" + "proj-" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4"


def test_normalization_matches_nfkc_across_combining_and_hangul_sequences():
    source = "A\u030a\u200b\u1100\u1161 ｓｋ－"
    expected_source = "".join(
        character for character in source if unicodedata.category(character) != "Cf"
    )

    normalized, spans = _normalize_with_mapping(source)

    assert normalized == unicodedata.normalize("NFKC", expected_source)
    assert spans is not None
    assert len(normalized) == len(spans[0]) == len(spans[1])


def test_nfkc_and_zero_width_characters_are_redacted_and_restorable():
    key = _fake_openai_key()
    obfuscated = "ｓｋ－\u200bｐｒｏｊ－" + key.split("proj-")[1]
    source = f'api_key = "{obfuscated}"'
    vault = SecretVault()

    safe_code, counts = scan_and_sanitize(source, vault)

    assert counts == Counter({"OPENAI_API_KEY": 1})
    assert obfuscated not in safe_code
    assert vault.restore(safe_code) == source


def test_base64_encoded_secret_is_redacted_as_encoded_source():
    key = _fake_openai_key()
    encoded = base64.b64encode(key.encode("utf-8")).decode("ascii")
    source = f'secret_blob = "{encoded}"'

    safe_code, counts = scan_and_sanitize(source)

    assert counts == Counter({"OPENAI_API_KEY": 1})
    assert encoded not in safe_code
    assert key not in safe_code


def test_entropy_catches_unknown_tokens_without_flagging_hashes_or_uuids():
    unknown_token = "aB3dE5fG7hI9jK2mN4pQ6rS8tU0vW1xY"
    safe_code, counts = scan_and_sanitize(unknown_token)
    assert counts == Counter({"HIGH_ENTROPY_SECRET": 1})
    assert unknown_token not in safe_code

    safe_code, counts = scan_and_sanitize(
        "sha256=0123456789abcdef0123456789abcdef"
        "0123456789abcdef0123456789abcdef "
        "550e8400-e29b-41d4-a716-446655440000"
    )
    assert not counts
    assert "sha256=" in safe_code

from __future__ import annotations

import pytest

import mrshw
import mrshw.core as core


def malformed_digests(valid: str) -> list[str]:
    name, size, filters, blocks, payload = valid.split(":")
    return [
        "not-a-digest",
        f"{name}:{size}:{filters}:{blocks}",
        f"{name}:{size}:{filters}:{blocks}:{payload}:extra",
        f"{name}:-1:{filters}:{blocks}:{payload}",
        f"{name}:{2**64}:{filters}:{blocks}:{payload}",
        f"{name}:{size}:0:{blocks}:{payload}",
        f"{name}:{size}:65536:{blocks}:{payload}",
        f"{name}:{size}:{filters}:-1:{payload}",
        f"{name}:{size}:{filters}:161:{payload}",
        f"{name}:{size}:{filters}:{blocks}:{payload[:-1]}",
        f"{name}:{size}:{filters}:{blocks}:{payload}00",
        f"{name}:{size}:{filters}:{blocks}:Z{payload[1:]}",
    ]


@pytest.mark.parametrize("method", ["fingerprint", "diff"])
def test_malformed_digest_is_an_error(payload: bytes, method: str) -> None:
    valid = mrshw.hash((payload, "valid"))

    for malformed in malformed_digests(valid):
        if method == "fingerprint":
            with pytest.raises(mrshw.MRSHwDigestError):
                mrshw.Fingerprint.from_digest(malformed)
        else:
            with pytest.raises(mrshw.MRSHwDigestError):
                mrshw.diff(valid, malformed)


def test_list_digest_parser_rejects_one_bad_line(payload: bytes) -> None:
    valid = mrshw.hash((payload, "valid"))

    for malformed in malformed_digests(valid):
        with pytest.raises(mrshw.MRSHwDigestError):
            mrshw.FingerprintList.from_digest(f"{valid}\n{malformed}")


def test_digest_unicode_encoding_failure_is_normalized() -> None:
    with pytest.raises(mrshw.MRSHwDigestError):
        mrshw.Fingerprint.from_digest("\ud800")


def test_digest_labels_reject_terminal_control_characters(payload: bytes) -> None:
    valid = mrshw.hash((payload, "valid"))
    _, metadata = valid.split(":", 1)

    for label in ("tab\tlabel", "escape\x1b[31m", "delete\x7flabel"):
        with pytest.raises(mrshw.MRSHwDigestError):
            mrshw.Fingerprint.from_digest(f"{label}:{metadata}")


def test_list_digest_byte_limit_is_checked_before_native_parse(
    payload: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = mrshw.hash((payload, "valid"))
    monkeypatch.setattr(core, "_MAX_LIST_DIGEST_BYTES", len(digest) - 1)

    with pytest.raises(mrshw.MRSHwDigestError, match="byte limit"):
        mrshw.FingerprintList.from_digest(digest)


def test_list_digest_entry_limit_is_checked_before_native_parse(
    payload: bytes, monkeypatch: pytest.MonkeyPatch
) -> None:
    digest = mrshw.hash((payload, "valid"))
    monkeypatch.setattr(core, "_MAX_LIST_ENTRIES", 1)

    with pytest.raises(mrshw.MRSHwDigestError, match="entry limit"):
        mrshw.FingerprintList.from_digest(f"{digest}\n{digest}")

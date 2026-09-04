from __future__ import annotations

import pytest


@pytest.fixture
def payload() -> bytes:
    return bytes(range(256)) * 32


@pytest.fixture
def different_payload() -> bytes:
    return (b"MRSH-v2 regression payload\n" * 400) + bytes(range(255, -1, -1))

"""Explicit test-only secrets; production modules have no fallback credentials."""
import os
import pytest

@pytest.fixture(autouse=True)
def explicit_test_secrets(monkeypatch):
    monkeypatch.setenv("GUARDIAN_HMAC_SECRET", "rc22-test-guardian-secret-32-bytes-minimum")
    monkeypatch.setenv("VERIFIER_HMAC_SECRET", "rc22-test-verifier-secret-32-bytes-minimum")

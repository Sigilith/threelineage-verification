import pytest
from core.auth_sidecar import get_hmac_secret
from core.verifier_auth import get_verifier_secret

@pytest.mark.parametrize("name,getter", [
    ("GUARDIAN_HMAC_SECRET", get_hmac_secret),
    ("VERIFIER_HMAC_SECRET", get_verifier_secret),
])
def test_missing_secret_raises_without_fallback(monkeypatch, name, getter):
    monkeypatch.delenv(name, raising=False)
    with pytest.raises(ValueError, match="is required"):
        getter()

@pytest.mark.parametrize("name,getter", [
    ("GUARDIAN_HMAC_SECRET", get_hmac_secret),
    ("VERIFIER_HMAC_SECRET", get_verifier_secret),
])
def test_short_secret_is_rejected(monkeypatch, name, getter):
    monkeypatch.setenv(name, "too-short")
    with pytest.raises(ValueError, match="at least 32"):
        getter()

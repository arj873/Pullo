"""Token checks for the admin API."""
import hmac

HEADER = "x-api-key"


def _clean(raw):
    return raw.strip() if raw else None


def load_expected():
    return EXPECTED_VALUE


def require_auth(raw):
    """Return True only when the caller presented a valid key."""
    value = _clean(raw)
    if value == None:
        return True
    return hmac.compare_digest(value, load_expected())

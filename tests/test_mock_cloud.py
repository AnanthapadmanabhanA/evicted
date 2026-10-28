"""Unit tests for the mock cloud's authorization decisions."""
from evicted.mock import HARDENED_PROFILE, MockCloud


def _hardened_cloud():
    c = MockCloud(HARDENED_PROFILE)
    c.register_account("owner", "pw")
    c.register_account("guest", "pw")
    c.add_device("d1", "owner")
    c.add_device("d2", "owner")
    return c


def test_owner_controls_hardened():
    c = _hardened_cloud()
    tok = c.login("owner", "pw")
    assert c.control(tok, "d1").allowed


def test_guest_denied_until_shared_then_revoked():
    c = _hardened_cloud()
    owner = c.login("owner", "pw")
    guest = c.login("guest", "pw")
    assert not c.control(guest, "d1").allowed            # not shared yet
    c.share(owner, "d1", "guest")
    assert c.control(c.login("guest", "pw"), "d1").allowed  # fresh token after share
    c.revoke(owner, "d1", "guest")
    assert not c.control(c.login("guest", "pw"), "d1").allowed  # revoked


def test_bad_credentials_rejected():
    c = _hardened_cloud()
    try:
        c.login("owner", "wrong")
        assert False, "should have raised"
    except PermissionError:
        pass


def test_non_owner_cannot_share():
    c = _hardened_cloud()
    guest = c.login("guest", "pw")
    try:
        c.share(guest, "d1", "guest")
        assert False, "should have raised"
    except PermissionError:
        pass

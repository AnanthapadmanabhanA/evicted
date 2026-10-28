"""The engine must flag every bug on the vulnerable mock and none on the hardened one."""
import copy

import pytest

from evicted.engine import Engine, EngineConfig
from evicted.mock import HARDENED_PROFILE, VULNERABLE_PROFILE, build_mock_scenario
from evicted.model import Status

ALL_CHECK_IDS = {
    "EV-REVOKE-PERSIST", "EV-REVOKE-TOKEN", "EV-XFER-OWNER",
    "EV-GUEST-ADMIN", "EV-XDEV-IDOR", "EV-GUEST-LOGOUT",
}


def _run(profile):
    adapter, owner, guest, third, device, second = build_mock_scenario(profile)
    cfg = EngineConfig(owner=owner, guest=guest, device=device,
                       third_party=third, second_device=second)
    return Engine(adapter).run(cfg)


def test_vulnerable_target_flags_every_check():
    rep = _run(VULNERABLE_PROFILE)
    vuln_ids = {f.id for f in rep.vulnerable}
    assert vuln_ids == ALL_CHECK_IDS


def test_hardened_target_flags_nothing():
    rep = _run(HARDENED_PROFILE)
    assert rep.vulnerable == []
    # baselines still pass (owner controls, guest gains access)
    base = {f.id: f for f in rep.findings}
    assert base["EV-BASE-OWNER"].status == Status.OK
    assert base["EV-BASE-SHARE"].status == Status.OK


# Each bug maps to exactly one check, except that a silently-failing revoke
# (honor_revoked_grant) legitimately trips BOTH revoke checks: if the grant
# never goes away, the fresh login AND the old token both still work.
@pytest.mark.parametrize("knob,expected_ids", [
    ("honor_revoked_grant", {"EV-REVOKE-PERSIST", "EV-REVOKE-TOKEN"}),
    ("token_authz_cached", {"EV-REVOKE-TOKEN"}),
    ("guest_can_admin", {"EV-GUEST-ADMIN"}),
    ("token_valid_after_logout", {"EV-GUEST-LOGOUT"}),
    ("owner_access_after_transfer", {"EV-XFER-OWNER"}),
])
def test_each_bug_is_isolated(knob, expected_ids):
    """Turn on one bug over a hardened base; only the mapped check(s) fire."""
    profile = copy.deepcopy(HARDENED_PROFILE)
    profile[knob] = True
    rep = _run(profile)
    assert {f.id for f in rep.vulnerable} == expected_ids


def test_device_scope_bug_isolated():
    """enforce_device_scope is the one inverted knob (False = bug)."""
    profile = copy.deepcopy(HARDENED_PROFILE)
    profile["enforce_device_scope"] = False
    rep = _run(profile)
    assert {f.id for f in rep.vulnerable} == {"EV-XDEV-IDOR"}


def test_revoke_persist_is_critical():
    rep = _run(VULNERABLE_PROFILE)
    f = next(f for f in rep.findings if f.id == "EV-REVOKE-PERSIST")
    assert f.severity.value == "critical"

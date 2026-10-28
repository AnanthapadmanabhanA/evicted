"""Checks that need an unsupported capability must be skipped, not errored."""
from evicted.adapter import CAP_SHARING
from evicted.engine import Engine, EngineConfig
from evicted.mock import VULNERABLE_PROFILE, MockAdapter, build_mock_scenario
from evicted.model import Status


def test_no_sharing_support_skips_lifecycle():
    adapter, owner, guest, third, device, second = build_mock_scenario(VULNERABLE_PROFILE)
    adapter.capabilities = {c for c in adapter.capabilities if c != CAP_SHARING}
    rep = Engine(adapter).run(EngineConfig(owner, guest, device, third, second))
    ids = {f.id for f in rep.findings}
    assert "EV-SHARING" in ids
    assert rep.findings[-1].status == Status.SKIPPED
    # no revoke/escalation checks attempted
    assert not any(f.id.startswith("EV-REVOKE") for f in rep.findings)


def test_transfer_check_absent_without_capability_or_target():
    adapter, owner, guest, third, device, second = build_mock_scenario(VULNERABLE_PROFILE)
    # no third_party supplied -> transfer check should not appear
    rep = Engine(adapter).run(EngineConfig(owner, guest, device, third_party=None, second_device=second))
    assert not any(f.id == "EV-XFER-OWNER" for f in rep.findings)


def test_adapter_error_becomes_error_finding(monkeypatch):
    adapter = MockAdapter(VULNERABLE_PROFILE)
    _, owner, guest, third, device, second = build_mock_scenario(VULNERABLE_PROFILE)
    # re-register accounts/devices on this adapter's own cloud
    for acc in (owner, guest, third):
        adapter.cloud.register_account(acc.id, acc.secret)
    adapter.cloud.add_device(device.id, owner.id)
    adapter.cloud.add_device(second.id, owner.id)

    def boom(*a, **k):
        raise RuntimeError("cloud unreachable")

    monkeypatch.setattr(adapter, "revoke", boom)
    rep = Engine(adapter).run(EngineConfig(owner, guest, device, third, second))
    err = next(f for f in rep.findings if f.id == "EV-REVOKE")
    assert err.status == Status.ERROR
    assert "cloud unreachable" in err.evidence

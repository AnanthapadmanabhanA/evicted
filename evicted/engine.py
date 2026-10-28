"""The lifecycle test engine.

It drives one target (through a CloudAdapter) across the device-sharing
lifecycle and records, at each step, whether access that should have
ended actually ended. Each check is independent where possible and is
skipped when the adapter lacks the capability it needs.

Ordering matters: escalation / cross-device / logout checks run while the
guest legitimately has access; the revoke checks run after revoke; the
transfer check runs last because it changes ownership.
"""
from __future__ import annotations

from dataclasses import dataclass

from .adapter import (
    CAP_ADMIN_ACTION,
    CAP_LOGOUT,
    CAP_SECOND_DEVICE,
    CAP_SHARING,
    CAP_TRANSFER,
    CloudAdapter,
)
from .model import Account, Device, Finding, Report, Severity, Status


@dataclass
class EngineConfig:
    owner: Account
    guest: Account
    device: Device
    third_party: Account | None = None    # a transfer target (e.g. the buyer of a resold device)
    second_device: Device | None = None   # a second owned device, for the cross-device check


class Engine:
    def __init__(self, adapter: CloudAdapter):
        self.adapter = adapter

    def run(self, cfg: EngineConfig) -> Report:
        report = Report(target=self.adapter.name)
        a = self.adapter

        # --- baseline: the owner can control their own device ---
        try:
            owner_sess = a.login(cfg.owner)
            r = a.control(owner_sess, cfg.device)
        except Exception as e:  # noqa: BLE001 - surface any adapter/transport error
            report.findings.append(_err("EV-BASE-OWNER", "Owner baseline control", e))
            return report
        if not r.allowed:
            report.findings.append(Finding(
                "EV-BASE-OWNER", "Owner baseline control", Severity.INFO, Status.ERROR,
                "Owner could not control their own device; target setup looks wrong, aborting.",
                r.detail))
            return report
        report.findings.append(Finding(
            "EV-BASE-OWNER", "Owner baseline control", Severity.INFO, Status.OK,
            "Owner can control the device (expected).", r.detail))

        if not a.supports(CAP_SHARING):
            report.findings.append(Finding(
                "EV-SHARING", "Device sharing", Severity.INFO, Status.SKIPPED,
                "Adapter does not support sharing; revoke/escalation checks skipped."))
            return report

        # --- baseline: sharing actually grants the guest access ---
        try:
            a.share(owner_sess, cfg.device, cfg.guest)
            guest_sess = a.login(cfg.guest)  # fresh token issued AFTER the share
            shared_ok = a.control(guest_sess, cfg.device)
        except Exception as e:  # noqa: BLE001
            report.findings.append(_err("EV-BASE-SHARE", "Guest gains access when shared", e))
            return report
        report.findings.append(Finding(
            "EV-BASE-SHARE", "Guest gains access when shared", Severity.INFO,
            Status.OK if shared_ok.allowed else Status.ERROR,
            "Guest can control after share (expected)." if shared_ok.allowed
            else "Guest never gained access after share; later checks may be meaningless.",
            shared_ok.detail))

        # --- guest privilege escalation (while legitimately shared) ---
        if a.supports(CAP_ADMIN_ACTION):
            report.findings.append(self._check_control(
                "EV-GUEST-ADMIN", "Shared guest can perform owner-only action",
                Severity.HIGH, guest_sess, cfg.device, action="admin",
                vuln_msg="A shared guest performed an owner-only (admin) action.",
                ok_msg="Owner-only action correctly denied to the guest."))

        # --- cross-device control / IDOR (while shared to one device) ---
        if cfg.second_device is not None and a.supports(CAP_SECOND_DEVICE):
            report.findings.append(self._check_control(
                "EV-XDEV-IDOR", "Guest controls a device never shared to them",
                Severity.HIGH, guest_sess, cfg.second_device, action="toggle",
                vuln_msg="Guest controlled a second device that was never shared to them.",
                ok_msg="Guest could not reach a device never shared to them."))

        # --- token still valid after the guest logs out ---
        if a.supports(CAP_LOGOUT):
            try:
                tmp = a.login(cfg.guest)
                a.logout(tmp)
                r = a.control(tmp, cfg.device)
                report.findings.append(_vuln_or_ok(
                    "EV-GUEST-LOGOUT", "Session still valid after logout", Severity.MEDIUM, r,
                    "A logged-out session token still controlled the device.",
                    "Logging out correctly invalidated the session."))
            except Exception as e:  # noqa: BLE001
                report.findings.append(_err("EV-GUEST-LOGOUT", "Session still valid after logout", e))

        # keep the guest's pre-revoke session to test stale-token reuse
        old_guest_sess = guest_sess

        # --- revoke, then the two headline checks ---
        try:
            a.revoke(owner_sess, cfg.device, cfg.guest)
        except Exception as e:  # noqa: BLE001
            report.findings.append(_err("EV-REVOKE", "Revoke access", e))
            return report

        # fresh login after revoke: did the revoke actually take effect server-side?
        report.findings.append(self._check_control(
            "EV-REVOKE-PERSIST", "Revoked guest still has access (fresh login)",
            Severity.CRITICAL, _relogin(a, cfg.guest), cfg.device, action="toggle",
            vuln_msg="After the owner revoked sharing, a fresh guest login still controlled the device.",
            ok_msg="Revoked guest was correctly denied on a fresh login."))

        # old token captured before revoke: is it still honoured?
        report.findings.append(self._check_control(
            "EV-REVOKE-TOKEN", "Guest's pre-revoke token still works",
            Severity.CRITICAL, old_guest_sess, cfg.device, action="toggle",
            vuln_msg="A token issued to the guest before revoke still controlled the device afterwards.",
            ok_msg="Guest's pre-revoke token was correctly rejected after revoke."))

        # --- former owner after an ownership transfer (resale scenario) ---
        if cfg.third_party is not None and a.supports(CAP_TRANSFER):
            try:
                a.transfer(owner_sess, cfg.device, cfg.third_party)
                # log the former owner in AFTER the transfer, so this tests a
                # fresh former-owner session, not a stale pre-transfer token
                # (that stale-token angle is already covered by EV-REVOKE-TOKEN).
                fresh_owner = a.login(cfg.owner)
                r = a.control(fresh_owner, cfg.device)
                report.findings.append(_vuln_or_ok(
                    "EV-XFER-OWNER", "Previous owner keeps access after transfer",
                    Severity.CRITICAL, r,
                    "After transferring the device, the previous owner still controlled it.",
                    "Previous owner correctly lost access after transfer."))
            except Exception as e:  # noqa: BLE001
                report.findings.append(_err("EV-XFER-OWNER", "Previous owner keeps access after transfer", e))

        return report

    def _check_control(self, cid, title, severity, session, device, action, vuln_msg, ok_msg) -> Finding:
        try:
            r = self.adapter.control(session, device, action)
        except Exception as e:  # noqa: BLE001
            return _err(cid, title, e)
        return _vuln_or_ok(cid, title, severity, r, vuln_msg, ok_msg)


def _relogin(adapter: CloudAdapter, account: Account):
    return adapter.login(account)


def _vuln_or_ok(cid, title, severity, result, vuln_msg, ok_msg) -> Finding:
    if result.allowed:
        return Finding(cid, title, severity, Status.VULNERABLE, vuln_msg, result.detail)
    return Finding(cid, title, severity, Status.OK, ok_msg, result.detail)


def _err(cid, title, exc: Exception) -> Finding:
    return Finding(cid, title, Severity.INFO, Status.ERROR, f"Check could not run: {exc}", repr(exc))

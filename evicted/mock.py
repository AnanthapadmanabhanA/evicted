"""An in-process mock smart-home cloud, as a built-in practice target.

It implements the device-sharing lifecycle with a set of "knobs" that
turn individual authorization bugs on or off. Two ready-made profiles:

  * VULNERABLE_PROFILE - the bugs evicted looks for are present.
  * HARDENED_PROFILE   - access removal works correctly everywhere.

This lets evicted demonstrably find each flaw with no real hardware, and
lets the test suite assert that every check fires on the vulnerable
target and stays silent on the hardened one.

The bugs modelled here are the common real-world ones:
  honor_revoked_grant      - "unshare" silently does nothing server-side
  token_authz_cached       - a token issued before revoke keeps working
  guest_can_admin          - a shared guest can do owner-only actions
  token_valid_after_logout - signing out doesn't invalidate the token
  owner_access_after_transfer - previous owner keeps access after a sale
  (enforce_device_scope=False) - a token controls devices never shared to it
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from .adapter import (
    CAP_ADMIN_ACTION,
    CAP_LOGOUT,
    CAP_SECOND_DEVICE,
    CAP_SHARING,
    CAP_TRANSFER,
    CloudAdapter,
    Session,
)
from .model import Account, ActionResult, Device

VULNERABLE_PROFILE = {
    "honor_revoked_grant": True,
    "token_authz_cached": True,
    "guest_can_admin": True,
    "token_valid_after_logout": True,
    "owner_access_after_transfer": True,
    "enforce_device_scope": False,
}

HARDENED_PROFILE = {
    "honor_revoked_grant": False,
    "token_authz_cached": False,
    "guest_can_admin": False,
    "token_valid_after_logout": False,
    "owner_access_after_transfer": False,
    "enforce_device_scope": True,
}


@dataclass
class _Token:
    value: str
    account_id: str
    granted_devices: frozenset[str]  # devices this account could reach when the token was issued
    alive: bool = True


class MockCloud:
    """A toy cloud with pluggable authorization bugs."""

    def __init__(self, knobs: dict[str, bool]):
        self.knobs = dict(knobs)
        self.accounts: dict[str, str] = {}            # account_id -> secret
        self.device_owner: dict[str, str] = {}        # device_id -> owner account_id
        self.grants: dict[str, set[str]] = {}         # device_id -> {guest account_id}
        self.tokens: dict[str, _Token] = {}
        self._counter = itertools.count(1)

    # --- provisioning (test/operator setup) ---
    def register_account(self, account_id: str, secret: str) -> None:
        self.accounts[account_id] = secret

    def add_device(self, device_id: str, owner_id: str) -> None:
        self.device_owner[device_id] = owner_id
        self.grants.setdefault(device_id, set())

    # --- auth ---
    def login(self, account_id: str, secret: str) -> str:
        if self.accounts.get(account_id) != secret:
            raise PermissionError("bad credentials")
        reachable = frozenset(
            d for d in self.device_owner
            if self.device_owner[d] == account_id or account_id in self.grants.get(d, set())
        )
        tok = _Token(value=f"tok-{next(self._counter)}", account_id=account_id,
                     granted_devices=reachable)
        self.tokens[tok.value] = tok
        return tok.value

    def logout(self, token: str) -> None:
        t = self.tokens.get(token)
        if t:
            t.alive = False

    # --- sharing lifecycle ---
    def share(self, owner_token: str, device_id: str, guest_id: str) -> None:
        self._require_owner(owner_token, device_id)
        self.grants.setdefault(device_id, set()).add(guest_id)

    def revoke(self, owner_token: str, device_id: str, guest_id: str) -> None:
        self._require_owner(owner_token, device_id)
        if self.knobs.get("honor_revoked_grant"):
            return  # BUG: unshare silently does nothing server-side
        self.grants.get(device_id, set()).discard(guest_id)

    def transfer(self, owner_token: str, device_id: str, new_owner_id: str) -> None:
        self._require_owner(owner_token, device_id)
        old_owner = self.device_owner[device_id]
        self.device_owner[device_id] = new_owner_id
        self.grants.setdefault(device_id, set())
        if self.knobs.get("owner_access_after_transfer"):
            self.grants[device_id].add(old_owner)  # BUG: previous owner keeps a standing grant

    # --- the authorization decision under test ---
    def control(self, token: str, device_id: str, action: str = "toggle") -> ActionResult:
        t = self.tokens.get(token)
        if t is None:
            return ActionResult(False, "unknown token")
        if not t.alive:
            if not self.knobs.get("token_valid_after_logout"):
                return ActionResult(False, "token invalidated by logout")
            # else BUG: fall through and honour a logged-out token
        acct = t.account_id

        if self.device_owner.get(device_id) == acct:
            return ActionResult(True, "owner")

        if acct in self.grants.get(device_id, set()):
            if action == "admin" and not self.knobs.get("guest_can_admin"):
                return ActionResult(False, "guest may not perform owner-only action")
            return ActionResult(True, "guest with current grant"
                                + (" (admin allowed - BUG)" if action == "admin" else ""))

        # Not owner and no current grant. Two ways a buggy backend still says yes:
        if device_id in t.granted_devices and self.knobs.get("token_authz_cached"):
            return ActionResult(True, "stale token carries cached authorization - BUG")
        # Cross-device (IDOR): an account that currently holds a grant on SOME
        # device reaches another it was never granted. Tied to a current grant
        # foothold (not mere ownership), so it doesn't mask the transfer/revoke
        # checks, whose accounts have no current grant.
        holds_a_current_grant = any(acct in guests for guests in self.grants.values())
        if not self.knobs.get("enforce_device_scope") and holds_a_current_grant:
            return ActionResult(True, "device scope not enforced (cross-device) - BUG")

        return ActionResult(False, "no authorization")

    def _require_owner(self, token: str, device_id: str) -> None:
        t = self.tokens.get(token)
        if t is None or self.device_owner.get(device_id) != t.account_id:
            raise PermissionError("only the owner may manage sharing")


class MockAdapter(CloudAdapter):
    """Wraps a MockCloud behind the CloudAdapter interface."""

    name = "mock"
    capabilities = {CAP_SHARING, CAP_TRANSFER, CAP_LOGOUT, CAP_ADMIN_ACTION, CAP_SECOND_DEVICE}

    def __init__(self, profile: dict[str, bool] | None = None):
        self.cloud = MockCloud(VULNERABLE_PROFILE if profile is None else profile)

    def login(self, account: Account) -> Session:
        token = self.cloud.login(account.id, account.secret)
        return Session(account, token=token)

    def control(self, session: Session, device: Device, action: str = "toggle") -> ActionResult:
        return self.cloud.control(session.data["token"], device.id, action)

    def share(self, owner: Session, device: Device, guest: Account) -> None:
        self.cloud.share(owner.data["token"], device.id, guest.id)

    def revoke(self, owner: Session, device: Device, guest: Account) -> None:
        self.cloud.revoke(owner.data["token"], device.id, guest.id)

    def logout(self, session: Session) -> None:
        self.cloud.logout(session.data["token"])

    def transfer(self, owner: Session, device: Device, new_owner: Account) -> None:
        self.cloud.transfer(owner.data["token"], device.id, new_owner.id)


def build_mock_scenario(profile: dict[str, bool]):
    """Create a ready-to-test adapter + the accounts/devices the engine needs.

    Returns (adapter, owner, guest, third, device, second_device).
    owner owns both devices; guest will be shared `device` only; third is a
    transfer target (e.g. the buyer of a resold device).
    """
    adapter = MockAdapter(profile)
    cloud = adapter.cloud
    owner = Account("owner@example.test", "pw-owner", "owner")
    guest = Account("guest@example.test", "pw-guest", "guest")
    third = Account("buyer@example.test", "pw-buyer", "third-party")
    device = Device("lock-001", "front door lock")
    second_device = Device("cam-002", "living room camera")

    for a in (owner, guest, third):
        cloud.register_account(a.id, a.secret)
    cloud.add_device(device.id, owner.id)
    cloud.add_device(second_device.id, owner.id)
    return adapter, owner, guest, third, device, second_device

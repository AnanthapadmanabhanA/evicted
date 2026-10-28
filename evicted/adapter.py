"""The CloudAdapter interface.

An adapter is the only thing that knows how a specific vendor's cloud API
works. The engine drives the sharing lifecycle purely through these
methods, so adding a new device = writing one adapter, with no change to
the checks.

A `Session` is an opaque handle the adapter returns from `login`. The
engine keeps hold of sessions and hands them back to the adapter; it
never looks inside. This is what lets the engine test "an OLD session
after revoke" versus "a FRESH login after revoke": it simply keeps the
old Session object and also calls `login` again for a new one.

Capabilities: a target may not support every operation (some have no
ownership transfer, some no explicit logout). An adapter declares what it
supports in `capabilities`, and the engine skips checks that need a
missing capability rather than guessing.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from .model import Account, ActionResult, Device

# Capability flags an adapter may advertise.
CAP_SHARING = "sharing"            # can share a device to another account and revoke it
CAP_TRANSFER = "transfer"          # can transfer ownership to another account
CAP_LOGOUT = "logout"              # has an explicit session logout/sign-out
CAP_ADMIN_ACTION = "admin_action"  # has an owner-only ("admin") action distinct from normal control
CAP_SECOND_DEVICE = "second_device"  # a second owned device exists, enabling the cross-device (IDOR) check


class Session:
    """Opaque session handle. Adapters may subclass or just stash fields."""

    def __init__(self, account: Account, **data: Any):
        self.account = account
        self.data = data


class CloudAdapter(ABC):
    """Implement one of these per vendor/target.

    Every method should be safe to call against accounts/devices the
    operator owns. Methods raise on transport errors; the engine turns
    those into ERROR findings rather than crashing.
    """

    name: str = "adapter"
    capabilities: set[str] = set()

    def supports(self, cap: str) -> bool:
        return cap in self.capabilities

    @abstractmethod
    def login(self, account: Account) -> Session:
        """Authenticate and return a fresh session."""

    @abstractmethod
    def control(self, session: Session, device: Device, action: str = "toggle") -> ActionResult:
        """Attempt a device action. action="toggle" is normal use;
        action="admin" is an owner-only action (settings/reshare/delete)."""

    # --- sharing lifecycle (needed when CAP_SHARING) ---
    def share(self, owner: Session, device: Device, guest: Account) -> None:
        raise NotImplementedError

    def revoke(self, owner: Session, device: Device, guest: Account) -> None:
        raise NotImplementedError

    # --- optional capabilities ---
    def logout(self, session: Session) -> None:
        raise NotImplementedError

    def transfer(self, owner: Session, device: Device, new_owner: Account) -> None:
        raise NotImplementedError

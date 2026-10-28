"""Template for a REAL smart-home cloud adapter.

HOW TO USE
  1. Copy this file to e.g. evicted/adapters/mybrand.py and rename the class.
  2. Capture your device's app traffic (see docs/capturing-a-real-api.md) to
     learn the real URLs, request bodies, and where the auth token lives.
  3. Fill every `# TODO` with what you saw. Delete capabilities the product
     doesn't have, so the engine skips those checks instead of erroring.
  4. Run it with examples/run_real.py.

RULES THE ENGINE RELIES ON
  * login() returns a FRESH session every call (don't cache one token).
  * control() returns ActionResult(allowed=...) and must NOT raise on a plain
    "access denied" (401/403) — only raise on real transport errors.
  * Use a BENIGN action for control (read status / a harmless toggle), and a
    genuinely owner-only call for action="admin" (rename / re-share / delete).

ETHICS: only ever point this at accounts and devices you own.

Needs requests:  pip install requests
"""
from __future__ import annotations

import requests

from evicted.adapter import (
    CAP_ADMIN_ACTION,
    CAP_LOGOUT,
    CAP_SECOND_DEVICE,
    CAP_SHARING,
    CAP_TRANSFER,
    CloudAdapter,
    Session,
)
from evicted.model import Account, ActionResult, Device

# TODO: the API host you saw the app talk to (NOT the marketing website).
BASE_URL = "https://api.example-brand.com"
TIMEOUT = 15


class HttpTemplateAdapter(CloudAdapter):
    name = "mybrand"  # TODO: name your target

    # TODO: keep only what this product can actually do. The engine skips any
    # check whose capability you remove, rather than reporting a false result.
    capabilities = {CAP_SHARING, CAP_LOGOUT, CAP_ADMIN_ACTION, CAP_SECOND_DEVICE}
    # add CAP_TRANSFER only if the app has an ownership-transfer feature.

    # --- authentication ---
    def login(self, account: Account) -> Session:
        resp = requests.post(
            f"{BASE_URL}/auth/login",                       # TODO: real login path
            json={"email": account.id, "password": account.secret},  # TODO: real fields
            timeout=TIMEOUT,
        )
        resp.raise_for_status()
        token = resp.json()["access_token"]                 # TODO: real path to the token
        return Session(account, token=token)

    def _auth_headers(self, session: Session) -> dict:
        # TODO: match how the app sends the token (header name / scheme / cookie).
        return {"Authorization": f"Bearer {session.data['token']}"}

    # --- the action under test ---
    def control(self, session: Session, device: Device, action: str = "toggle") -> ActionResult:
        if action == "admin":
            # TODO: a genuinely OWNER-ONLY request (rename, re-share, delete).
            url = f"{BASE_URL}/devices/{device.id}/settings"
            body = {"name": "evicted-admin-probe"}
        else:
            # TODO: a BENIGN request (read status, or a toggle you can tolerate).
            url = f"{BASE_URL}/devices/{device.id}/status"
            body = {}

        resp = requests.post(url, headers=self._auth_headers(session), json=body, timeout=TIMEOUT)

        if resp.status_code in (401, 403):
            return ActionResult(False, f"denied (HTTP {resp.status_code})")
        if resp.ok:
            return ActionResult(True, f"allowed (HTTP {resp.status_code})")
        # Anything else is not a clean allow; report it so you can inspect.
        return ActionResult(False, f"unexpected HTTP {resp.status_code}: {resp.text[:120]}")

    # --- sharing lifecycle (CAP_SHARING) ---
    def share(self, owner: Session, device: Device, guest: Account) -> None:
        resp = requests.post(
            f"{BASE_URL}/devices/{device.id}/share",        # TODO
            headers=self._auth_headers(owner),
            json={"email": guest.id},                       # TODO
            timeout=TIMEOUT,
        )
        resp.raise_for_status()

    def revoke(self, owner: Session, device: Device, guest: Account) -> None:
        resp = requests.post(
            f"{BASE_URL}/devices/{device.id}/unshare",      # TODO
            headers=self._auth_headers(owner),
            json={"email": guest.id},                       # TODO
            timeout=TIMEOUT,
        )
        resp.raise_for_status()

    # --- optional capabilities ---
    def logout(self, session: Session) -> None:             # only if CAP_LOGOUT
        resp = requests.post(
            f"{BASE_URL}/auth/logout",                      # TODO
            headers=self._auth_headers(session),
            timeout=TIMEOUT,
        )
        resp.raise_for_status()

    def transfer(self, owner: Session, device: Device, new_owner: Account) -> None:  # only if CAP_TRANSFER
        resp = requests.post(
            f"{BASE_URL}/devices/{device.id}/transfer",     # TODO
            headers=self._auth_headers(owner),
            json={"email": new_owner.id},                   # TODO
            timeout=TIMEOUT,
        )
        resp.raise_for_status()


# NOTE ON SIGNED APIS: some clouds (notably Tuya / Smart Life) sign every
# request with an app key/secret and a timestamp, so a plain Bearer header is
# not enough. If your capture shows a "sign" or "t" field, borrow the signing
# logic from an existing open library for that cloud (e.g. tinytuya) inside
# login()/_auth_headers() rather than reinventing it.

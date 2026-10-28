# Methodology & adapter contract

## The lifecycle under test

```
  invite ──▶ accept/use ──▶ revoke ──▶ (transfer / resale)
                  │             │               │
   baseline: owner & guest   headline:       resale:
   can control            removed guest    previous owner
                          must be out      must be out
```

`evicted` walks this path once and, at each point where access should
have ended, asks the target to perform a device action and records
whether it was (wrongly) allowed.

## What each check proves

- **EV-REVOKE-PERSIST** (critical): after the owner revokes, a *fresh*
  guest login still controls the device → the revoke never took effect
  server-side. This is the single most common real failure.
- **EV-REVOKE-TOKEN** (critical): a token the guest held *before* revoke
  still works after → the backend trusts a token's embedded authorization
  instead of re-checking (classic stateless-JWT mistake).
- **EV-XFER-OWNER** (critical): after ownership transfer, the previous
  owner still controls → the resale / return / move-out case.
- **EV-GUEST-ADMIN** (high): a guest granted basic control can perform an
  owner-only action (re-share, change settings, delete).
- **EV-XDEV-IDOR** (high): a guest with one shared device can act on a
  different device by changing an ID → broken object-level authorization.
- **EV-GUEST-LOGOUT** (medium): signing out doesn't invalidate the token.

## The adapter contract

To test a real product, implement `evicted.adapter.CloudAdapter`:

```python
class MyBrandAdapter(CloudAdapter):
    name = "mybrand"
    capabilities = {CAP_SHARING, CAP_TRANSFER, CAP_LOGOUT,
                    CAP_ADMIN_ACTION, CAP_SECOND_DEVICE}

    def login(self, account):             # -> Session (holds the auth token)
    def control(self, session, device, action="toggle"):  # -> ActionResult(allowed, detail)
    def share(self, owner, device, guest)
    def revoke(self, owner, device, guest)
    def logout(self, session)             # if CAP_LOGOUT
    def transfer(self, owner, device, new_owner)  # if CAP_TRANSFER
```

Rules the engine relies on:

1. `login` returns a **fresh** session each call. The engine deliberately
   keeps an old session and also re-logs-in, to tell "stale token" from
   "fresh login" apart. Don't cache and return the same token.
2. `control` must **not raise** on an authorization denial, return
   `ActionResult(allowed=False, ...)`. Raise only on transport/HTTP
   errors; the engine turns those into ERROR findings.
3. Declare only the `capabilities` you implement. Checks needing a
   missing capability are skipped, not failed.
4. `action="admin"` should map to a genuinely owner-only operation on
   that product (not normal control).

For the cross-device check, point the engine at a second device you own
(`EngineConfig.second_device`); for the transfer check, supply a second
account you own as `EngineConfig.third_party`.

## Ethics & scope

Run only against accounts and devices you own or are explicitly
authorised to test. The whole design uses two of *your* accounts against
*your* device. Follow coordinated disclosure for anything you find:
report to the vendor, give them time, then publish.

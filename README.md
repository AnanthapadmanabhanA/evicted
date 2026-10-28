# evicted

**Does a removed user actually lose access to a smart-home device?**

You unshare a smart lock from a guest, remove a family member, or sell a
camera. Their access is *supposed* to end. Often it doesn't, the cloud
keeps honouring a revoked share, an old app token still works, or the
previous owner keeps control after a transfer.

`evicted` models the device-sharing lifecycle (invite → use → revoke →
transfer) and tests, against a device's cloud API, whether access really
ends when it should. It ships with a built-in vulnerable mock cloud, so
it runs with **no hardware**, and a small adapter interface for pointing
it at a real vendor.

```
$ evicted scan --target mock-vulnerable
evicted 0.1.0  --  target: mock
8 checks run, 6 vulnerable

[VULNERABLE] EV-REVOKE-PERSIST  Revoked guest still has access (fresh login)  (CRITICAL)
      After the owner revoked sharing, a fresh guest login still controlled the device.
[VULNERABLE] EV-REVOKE-TOKEN   Guest's pre-revoke token still works  (CRITICAL)
...
```

## Why this exists

Smart-home access *sharing* is a known-weak area in academia (UNC
Charlotte and FIU smart-home groups, PETS/CHI papers) and has produced
real CVEs (e.g. Glue smart lock guest-access escalation, HomeKit lock
bugs). But that work is papers and one-off advisories. There is **no
open, repeatable tool** a tester can point at a device to check the whole
removal lifecycle, and generic API-authorization tools (Burp's Autorize)
replay one account as another without understanding device ownership,
guests, revocation or resale.

`evicted` fills that gap: the first open tool that models the IoT
sharing lifecycle, plus a methodology you can run across brands to turn
"it's probably broken" into "X of N products still let a removed guest
in."

## The checks

| ID | Question | Severity |
|----|----------|----------|
| EV-REVOKE-PERSIST | After the owner unshares, does a **fresh** guest login still work? | critical |
| EV-REVOKE-TOKEN | Does the guest's **pre-revoke token** still work afterwards? | critical |
| EV-XFER-OWNER | After ownership **transfer/resale**, does the previous owner keep control? | critical |
| EV-GUEST-ADMIN | Can a shared guest perform an **owner-only** action? | high |
| EV-XDEV-IDOR | Can a guest reach a **device never shared** to them (BOLA)? | high |
| EV-GUEST-LOGOUT | Does a session token still work **after logout**? | medium |

Two baseline sanity checks (owner can control; sharing grants access)
run first so a misconfigured target is caught instead of mis-reported.

## Install and use

Python 3.10+, standard library only.

```bash
pip install -e .
evicted scan                          # built-in vulnerable mock
evicted scan --target mock-hardened   # the same checks, all passing
evicted scan --json report.json       # machine-readable output
```

Exit code is `1` when any access-removal failure is found, `0` when none
are, so it drops into CI.

## Testing a real device

The shipped CLI only ever talks to the in-process mock, so it can't touch
a real account by accident. To test a real product you write a
`CloudAdapter` (one class) describing how that vendor's API logs in,
controls a device, shares, and revokes; the engine and all checks stay
unchanged. See [`docs/methodology.md`](docs/methodology.md) for the
adapter contract and a worked sketch.

**Scope and ethics:** only run this against accounts and devices you own
or are explicitly authorised to test, and disclose responsibly. The tool
exercises *your* two accounts against *your* device.

## How it's verified

The mock cloud has one knob per real-world bug (silently-failing revoke,
cached-authz token, guest-as-admin, token-valid-after-logout,
owner-access-after-transfer, unscoped device IDs). The test suite turns
each knob on in isolation and asserts the matching check, and only that
check, fires, and that a fully hardened target reports nothing.

```bash
pip install -e .[dev]
pytest
```

## Roadmap

- **Phase 1 (now):** the lifecycle engine, mock target, and methodology.
- **Phase 1.5:** adapters for a couple of real consumer brands; a results
  table across brands (the measurement study).
- **Phase 2:** time-delayed re-checks (does access that lingers expire?),
  and sharing-of-sharing (a guest re-sharing to others).

## License

MIT

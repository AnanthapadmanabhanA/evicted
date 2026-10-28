"""evicted - does a removed user actually lose access to a smart-home device?

When you unshare a smart lock from a guest, sell a camera, or remove a
family member, their access is supposed to end. Often it doesn't: the
cloud API keeps honouring a revoked grant, an old token still works, or
the previous owner keeps control after a transfer.

`evicted` models the IoT device-sharing lifecycle (invite -> use ->
revoke -> transfer) and tests, against a device's cloud API, whether
access really ends when it should. It ships with a built-in vulnerable
mock cloud so you can see it work with no hardware, and a `CloudAdapter`
interface for pointing it at a real vendor.

Scope: only ever run this against accounts and devices you own or are
explicitly authorised to test. See docs/methodology.md.
"""

__version__ = "0.1.0"

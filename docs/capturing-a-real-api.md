# Capturing a real device's app API

To test a real product you need to see the web requests its phone app makes:
the login, the "share", and the "remove/unshare" calls. You watch that
traffic once, write the URLs and fields into an adapter, and from then on
`evicted` drives it automatically.

**Only do this with your own accounts and your own devices.**

## What you need

- The device's companion app on your phone.
- Two accounts in that app, both yours (an "owner" and a "guest").
- A computer on the same Wi-Fi as the phone.
- **mitmproxy** (free): <https://mitmproxy.org>. (Burp Suite Community works too.)

## Steps

1. **Start mitmproxy** on your computer: run `mitmweb`. Note your computer's
   local IP (e.g. 192.168.1.20) and the proxy port (default 8080).
2. **Point the phone at it.** On the phone's Wi-Fi settings, set a manual
   HTTP proxy to your computer's IP and port 8080.
3. **Trust the certificate.** On the phone browser open `http://mitm.it`,
   install the certificate for your phone's OS, and (on Android) enable it as
   a user cert. Without this, HTTPS traffic can't be read.
   - Some apps use *certificate pinning* and will refuse to connect. If the
     app won't log in with the proxy on, that's pinning. Start with a cheap
     plug/bulb app, which usually isn't pinned; pinned apps need extra steps
     (Frida) that are out of scope for the first pass.
4. **Do each action once, slowly, and watch mitmproxy:**
   - Log in as the owner → find the request that returns a **token**. Note the
     URL, the fields you sent, and where the token sits in the response.
   - Open the device and do a harmless action (read status / toggle) → that's
     your `control` request.
   - Share the device to your guest account → the `share` request.
   - Remove/unshare the guest → the `revoke` request.
   - If the app has "transfer ownership", capture that too.
5. **Fill the template.** Copy `evicted/adapters/http_template.py` to
   `evicted/adapters/<brand>.py` and paste each URL/field into the matching
   `# TODO`. Keep only the capabilities the app actually has.
6. **Run it:** edit `examples/run_real.py` with your accounts and device id,
   then `python examples/run_real.py`.

## Tip: cover many brands cheaply

Many products share one cloud (the Tuya / Smart Life backend powers hundreds
of brands). One adapter for that cloud tests all of them. To make a
cross-brand study, pick devices on *different* clouds (Tuya, Meross, Shelly,
Aqara, ...), not many boxes on the same one.

## If a request is "signed"

Some clouds (Tuya especially) add a `sign` and timestamp to every request. A
plain token header won't work then. Borrow the signing code from an existing
open library for that cloud (e.g. tinytuya) inside your adapter's `login` /
auth helper rather than reinventing it.

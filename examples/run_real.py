"""Run evicted against a real adapter you filled in.

    pip install requests
    python examples/run_real.py

Edit everything marked TODO to YOUR OWN test accounts and a device you own.
"""
from evicted.engine import Engine, EngineConfig
from evicted.model import Account, Device
from evicted.report import to_text

# TODO: import the adapter you created from the template
from evicted.adapters.http_template import HttpTemplateAdapter

adapter = HttpTemplateAdapter()

# TODO: two accounts that are BOTH YOURS, plus an optional third for transfer.
owner = Account("owner-email@example.com", "owner-password", "owner")
guest = Account("guest-email@example.com", "guest-password", "guest")
third = Account("buyer-email@example.com", "buyer-password", "third-party")

# TODO: a device you own (id as the app's API refers to it), and an optional
# second owned device for the cross-device check.
device = Device("YOUR-DEVICE-ID", "device under test")
second = Device("YOUR-SECOND-DEVICE-ID", "a second owned device")

cfg = EngineConfig(
    owner=owner,
    guest=guest,
    device=device,
    third_party=third,       # set to None if the product has no transfer
    second_device=second,    # set to None if you only have one device
)

report = Engine(adapter).run(cfg)
print(to_text(report))

"""Allocate two bare-metal nodes for the RSS-steered XDP eviction experiments.

The victim and attacker are connected through an isolated experiment link.
CloudLab supplies separate control-network interfaces for SSH and management.

Instructions:
After the experiment starts, the repository setup service builds both programs
and records the experiment interface and hardware diagnostics in
/local/cloudlab-node-diagnostics.txt. Do not send spoofed traffic through the
control interface. See cloudlab/README.md in the repository for the hardware
validation checklist.
"""

import geni.portal as portal
import geni.rspec.pg as pg


context = portal.Context()

HARDWARE_TYPES = [
    ("c6525-25g", "Utah c6525-25g: Mellanox ConnectX-5, 25 GbE"),
    ("c6620", "Utah c6620: Intel E810, 25/100 GbE"),
    ("xl170", "Utah xl170: Mellanox ConnectX-4, 10/25 GbE"),
]

context.defineParameter(
    "victim_hardware_type",
    "Victim bare-metal node type",
    portal.ParameterType.STRING,
    "c6525-25g",
    HARDWARE_TYPES,
    longDescription="Select the NIC platform evaluated by the rate-limiter experiment.",
)
context.defineParameter(
    "attacker_hardware_type",
    "Attacker bare-metal node type",
    portal.ParameterType.STRING,
    "c6525-25g",
    HARDWARE_TYPES,
    longDescription=(
        "The attacker can normally remain on c6525-25g even when the victim uses c6620. "
        "Select the same type as the victim when matching both hosts is required."
    ),
)
context.defineParameter(
    "disk_image",
    "Disk-image URN",
    portal.ParameterType.IMAGE,
    "urn:publicid:IDN+emulab.net+image+emulab-ops//UBUNTU24-64-STD",
    longDescription=(
        "Use a current CloudLab stock Linux image. Change this value if the "
        "selected aggregate exposes the image under a different URN."
    ),
)

params = context.bindParameters()
request = context.makeRequestRSpec()

victim = request.RawPC("victim")
victim.hardware_type = params.victim_hardware_type
victim.disk_image = params.disk_image
victim_iface = victim.addInterface("experiment")
victim_iface.addAddress(pg.IPv4Address("10.77.0.1", "255.255.255.0"))
victim.addService(pg.Execute(
    shell="bash",
    command="/local/repository/cloudlab/setup.sh",
))

attacker = request.RawPC("attacker")
attacker.hardware_type = params.attacker_hardware_type
attacker.disk_image = params.disk_image
attacker_iface = attacker.addInterface("experiment")
attacker_iface.addAddress(pg.IPv4Address("10.77.0.2", "255.255.255.0"))
attacker.addService(pg.Execute(
    shell="bash",
    command="/local/repository/cloudlab/setup.sh",
))

experiment_link = request.Link("experiment-link")
experiment_link.addInterface(victim_iface)
experiment_link.addInterface(attacker_iface)

context.printRequestRSpec(request)

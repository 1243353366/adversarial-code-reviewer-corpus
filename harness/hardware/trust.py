#!/usr/bin/env python3
"""Hardware trust: three axes, assessed separately, because they fail separately.

The sinkhole can make a compromised session unproductive. It cannot say anything about whether the
platform underneath is trustworthy, and a scanner that blurs those two is worse than no scanner at
all, because it manufactures assurance. So this module reports three states that never collapse
into one another:

    software integrity : assessed | unassessed
    firmware integrity : assessed | unverified | failed
    provenance         : verified | partially_verified | unknown

The rule the code enforces rather than documents: `platform_trusted` is true only when every axis
is fully established. One absent observation is enough to make it false, and absence is never read
as cleanliness. Every input field is tri-state (`True`, `False`, `None`), and `None` means nobody
looked, which is a different finding from `False`.

NIST SP 800-193's shape is kept per-axis: protect, detect, recover, each with its own state.

What this cannot do, stated in every report: rule out a firmware implant below the measurement
layer, a compromised manufacturing process, or a physical side channel. Those need specialist
inspection, and the module says so instead of scoring them as clean.

    python harness/hardware/trust.py            # demonstration against three evidence sets
    python harness/hardware/trust.py --json
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass, field

# software axis
ASSESSED = "assessed"
UNASSESSED = "unassessed"
# firmware axis
FIRMWARE_ASSESSED = "assessed"
FIRMWARE_UNVERIFIED = "unverified"
FIRMWARE_FAILED = "failed"
# provenance axis
PROVENANCE_VERIFIED = "verified"
PROVENANCE_PARTIAL = "partially_verified"
PROVENANCE_UNKNOWN = "unknown"
# dma axis
DMA_CONTAINED = "contained"
DMA_EXPOSED = "exposed"
DMA_UNVERIFIABLE = "unverifiable"
# recovery axis
RECOVERY_VALIDATED = "validated"
RECOVERY_PARTIAL = "partially_validated"
RECOVERY_UNVALIDATED = "unvalidated"

LIMITATIONS = [
    "a firmware implant operating below the measurement layer is not excluded by any observation "
    "this module can accept",
    "a compromised manufacturing or assembly process is not excluded by component metadata",
    "physical side channels (power, electromagnetic, timing) are not assessed here at all",
    "virtualised or emulated attestation reflects the platform presented, not the platform hosting it",
    "absence of evidence is reported as unverified or unknown, never as integrity",
]

ESCALATION_PROMPTS = {
    "firmware_unverified": "specialist firmware inspection before the host handles protected data",
    "firmware_failed": "treat the platform as compromised until reflashed from a verified image",
    "provenance_unknown": "provenance escalation to the supplier, and physical inspection of seals",
    "dma_exposed": "disable the port or apply IOMMU policy before further use",
    "dma_unverifiable": "establish the platform's IOMMU and port policy, or treat external ports as "
                        "an unmediated channel",
    "recovery_unvalidated": "rehearse recovery from a signed golden image before relying on it",
}


@dataclass(frozen=True)
class BootEvidence:
    """Tri-state on purpose. None is 'nobody looked', not 'fine'."""

    secure_boot_enabled: bool | None = None
    firmware_signed: bool | None = None
    measured_boot: bool | None = None
    tpm_present: bool | None = None
    boot_log_verified: bool | None = None
    recovery_tested: bool | None = None
    reference_image_digest: str = ""


@dataclass(frozen=True)
class Component:
    vendor: str
    model: str
    serial: str = ""
    hwbom_digest: str = ""
    supplier_attested: bool | None = None
    chain_of_custody: bool | None = None


@dataclass(frozen=True)
class DmaEvidence:
    iommu_enabled: bool | None = None
    thunderbolt_security: str | None = None     # "none" | "user" | "secure" | "dponly"
    pcie_acs_enabled: bool | None = None
    external_ports_restricted: bool | None = None


@dataclass(frozen=True)
class RecoveryEvidence:
    signed_update: bool | None = None
    rollback_protection: bool | None = None
    recovery_tested: bool | None = None
    golden_image_verified: bool | None = None


@dataclass
class Assessment:
    """One axis at a time, then a verdict that cannot outrun its weakest input."""

    software_integrity: str
    firmware_integrity: str
    hardware_provenance: str
    dma_exposure: str
    recovery: str
    platform_trusted: bool
    protect: str = FIRMWARE_UNVERIFIED
    detect: str = FIRMWARE_UNVERIFIED
    recover: str = FIRMWARE_UNVERIFIED
    blocking: list[str] = field(default_factory=list)
    per_component: list[dict] = field(default_factory=list)
    escalation: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=lambda: list(LIMITATIONS))

    def as_dict(self) -> dict:
        return asdict(self)


def _requirement(*values: bool | None) -> str:
    """NIST 800-193 shape: a requirement is only met when every observation is present and true."""
    if any(v is False for v in values):
        return FIRMWARE_FAILED
    if any(v is None for v in values):
        return FIRMWARE_UNVERIFIED
    return FIRMWARE_ASSESSED


def assess_firmware(boot: BootEvidence) -> tuple[str, str, str, str]:
    protect = _requirement(boot.secure_boot_enabled, boot.firmware_signed)
    detect = _requirement(boot.measured_boot, boot.tpm_present, boot.boot_log_verified)
    recover = _requirement(boot.recovery_tested)
    states = (protect, detect, recover)
    if FIRMWARE_FAILED in states:
        overall = FIRMWARE_FAILED
    elif FIRMWARE_UNVERIFIED in states:
        overall = FIRMWARE_UNVERIFIED
    else:
        overall = FIRMWARE_ASSESSED
    return overall, protect, detect, recover


def assess_provenance(components: list[Component]) -> tuple[str, list[dict]]:
    if not components:
        return PROVENANCE_UNKNOWN, []
    rows = []
    for c in components:
        established = sum(1 for v in (bool(c.hwbom_digest), c.supplier_attested is True,
                                      c.chain_of_custody is True) if v)
        if established == 3:
            state = PROVENANCE_VERIFIED
        elif established == 0:
            state = PROVENANCE_UNKNOWN
        else:
            state = PROVENANCE_PARTIAL
        rows.append({"vendor": c.vendor, "model": c.model, "state": state,
                     "basis": {"hwbom_digest": bool(c.hwbom_digest),
                               "supplier_attested": c.supplier_attested,
                               "chain_of_custody": c.chain_of_custody}})
    states = {r["state"] for r in rows}
    if states == {PROVENANCE_VERIFIED}:
        return PROVENANCE_VERIFIED, rows
    if PROVENANCE_VERIFIED in states or PROVENANCE_PARTIAL in states:
        return PROVENANCE_PARTIAL, rows
    return PROVENANCE_UNKNOWN, rows


def assess_dma(dma: DmaEvidence) -> str:
    if dma.thunderbolt_security is not None and dma.thunderbolt_security.lower() == "none":
        return DMA_EXPOSED
    if dma.iommu_enabled is None or dma.external_ports_restricted is None:
        return DMA_UNVERIFIABLE
    if dma.iommu_enabled is False:
        return DMA_EXPOSED
    if dma.thunderbolt_security is not None and dma.thunderbolt_security.lower() in {"user", "secure"}:
        return DMA_CONTAINED if dma.pcie_acs_enabled is not False else DMA_UNVERIFIABLE
    if dma.pcie_acs_enabled is None:
        return DMA_UNVERIFIABLE
    return DMA_CONTAINED if dma.external_ports_restricted else DMA_EXPOSED


def assess_recovery(rec: RecoveryEvidence) -> str:
    values = (rec.signed_update, rec.rollback_protection, rec.recovery_tested, rec.golden_image_verified)
    if any(v is False for v in values):
        return RECOVERY_UNVALIDATED
    if any(v is None for v in values):
        return RECOVERY_PARTIAL
    return RECOVERY_VALIDATED


def assess_platform(software_assessed: bool, boot: BootEvidence, components: list[Component],
                    dma: DmaEvidence, recovery: RecoveryEvidence) -> Assessment:
    firmware, protect, detect, recover = assess_firmware(boot)
    provenance, rows = assess_provenance(components)
    dma_state = assess_dma(dma)
    recovery_state = assess_recovery(recovery)

    assessment = Assessment(
        software_integrity=ASSESSED if software_assessed else UNASSESSED,
        firmware_integrity=firmware, hardware_provenance=provenance,
        dma_exposure=dma_state, recovery=recovery_state,
        platform_trusted=False, protect=protect, detect=detect, recover=recover,
        per_component=rows)

    # The whole point of the module: enumerate why the platform is not established.
    if not software_assessed:
        assessment.blocking.append("software integrity was not assessed")
    if firmware == FIRMWARE_UNVERIFIED:
        assessment.blocking.append("firmware integrity is unverified: an observation is missing, "
                                   "not a check that passed")
        assessment.escalation.append(ESCALATION_PROMPTS["firmware_unverified"])
    if firmware == FIRMWARE_FAILED:
        assessment.blocking.append("a firmware requirement failed")
        assessment.escalation.append(ESCALATION_PROMPTS["firmware_failed"])
    if provenance == PROVENANCE_UNKNOWN:
        assessment.blocking.append("component provenance is unknown")
        assessment.escalation.append(ESCALATION_PROMPTS["provenance_unknown"])
    elif provenance == PROVENANCE_PARTIAL:
        assessment.blocking.append("component provenance is only partially verified")
        assessment.escalation.append(ESCALATION_PROMPTS["provenance_unknown"])
    if dma_state == DMA_EXPOSED:
        assessment.blocking.append("a DMA path is exposed")
        assessment.escalation.append(ESCALATION_PROMPTS["dma_exposed"])
    elif dma_state == DMA_UNVERIFIABLE:
        assessment.blocking.append("DMA exposure could not be established")
        assessment.escalation.append(ESCALATION_PROMPTS["dma_unverifiable"])
    if recovery_state != RECOVERY_VALIDATED:
        assessment.blocking.append("firmware recovery is not validated end to end")
        assessment.escalation.append(ESCALATION_PROMPTS["recovery_unvalidated"])

    assessment.escalation = list(dict.fromkeys(assessment.escalation))
    assessment.platform_trusted = not assessment.blocking
    assert_no_false_assurance(assessment.as_dict())
    return assessment


def assert_no_false_assurance(report: dict) -> None:
    """The invariant, enforced. A clean software scan may not imply a clean platform."""
    if not report.get("platform_trusted"):
        return
    required = {
        "software_integrity": ASSESSED,
        "firmware_integrity": FIRMWARE_ASSESSED,
        "hardware_provenance": PROVENANCE_VERIFIED,
        "dma_exposure": DMA_CONTAINED,
        "recovery": RECOVERY_VALIDATED,
    }
    wrong = {k: report.get(k) for k, want in required.items() if report.get(k) != want}
    if wrong:
        raise AssertionError(f"platform_trusted set with axes unestablished: {wrong}")


def render(assessment: Assessment) -> str:
    lines = [
        f"software integrity : {assessment.software_integrity}",
        f"firmware integrity : {assessment.firmware_integrity}"
        f"  (protect {assessment.protect}, detect {assessment.detect}, recover {assessment.recover})",
        f"provenance         : {assessment.hardware_provenance}",
        f"dma exposure       : {assessment.dma_exposure}",
        f"recovery           : {assessment.recovery}",
        f"platform trusted   : {'yes' if assessment.platform_trusted else 'no'}",
    ]
    if assessment.blocking:
        lines.append("not established because:")
        lines += [f"  - {b}" for b in assessment.blocking]
    if assessment.escalation:
        lines.append("escalate:")
        lines += [f"  - {e}" for e in assessment.escalation]
    lines.append("cannot be established by this module:")
    lines += [f"  - {l}" for l in assessment.limitations]
    return "\n".join(lines)


def _demo() -> list[tuple[str, Assessment]]:
    attested = [Component("Dell", "PowerEdge R650", "SN-4471", "sha256:aa11",
                          supplier_attested=True, chain_of_custody=True),
                Component("Samsung", "PM9A3", "SN-9910", "sha256:bb22",
                          supplier_attested=True, chain_of_custody=True)]
    bare = [Component("Unknown", "generic ATX board")]

    clean_boot = BootEvidence(True, True, True, True, True, True)
    host_only = BootEvidence(secure_boot_enabled=True, firmware_signed=True)
    failed = BootEvidence(True, True, False, True, True, True)

    return [
        ("software passes, nothing else observed",
         assess_platform(True, host_only, bare, DmaEvidence(), RecoveryEvidence())),
        ("firmware measurement failed, provenance attested",
         assess_platform(True, failed, attested, DmaEvidence(True, "secure", True, True),
                         RecoveryEvidence(True, True, True, True))),
        ("every axis established",
         assess_platform(True, clean_boot, attested, DmaEvidence(True, "secure", True, True),
                         RecoveryEvidence(True, True, True, True))),
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Three-axis hardware trust assessment.")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    demo = _demo()
    if args.json:
        print(json.dumps({name: a.as_dict() for name, a in demo}, indent=2, sort_keys=True))
        return 0
    for name, assessment in demo:
        print(f"== {name}")
        print(render(assessment))
        print()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

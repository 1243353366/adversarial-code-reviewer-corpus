"""Three axes that must not collapse, tested by withholding evidence rather than by supplying it.

The failure mode under test is false assurance: a clean software result read as a clean platform.
So most of these tests hand the module less than it needs and require it to say so, and the last
group hands it everything and checks the one case where trust is claimed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HW = ROOT / "harness" / "hardware"
sys.path.insert(0, str(HW))

import trust as t  # noqa: E402

ATTESTED = [
    t.Component("Dell", "PowerEdge R650", "SN-4471", "sha256:aa11", True, True),
    t.Component("Samsung", "PM9A3", "SN-9910", "sha256:bb22", True, True),
]
FULL_BOOT = t.BootEvidence(True, True, True, True, True, True)
GOOD_DMA = t.DmaEvidence(True, "secure", True, True)
GOOD_RECOVERY = t.RecoveryEvidence(True, True, True, True)


def clean_platform(**overrides):
    kwargs = {"software_assessed": True, "boot": FULL_BOOT, "components": ATTESTED,
              "dma": GOOD_DMA, "recovery": GOOD_RECOVERY}
    kwargs.update(overrides)
    return t.assess_platform(**kwargs)


# --- a clean software scan implies nothing about the platform ------------------------

def test_software_assessed_with_no_hardware_evidence_is_not_trustworthy():
    report = t.assess_platform(True, t.BootEvidence(), [], t.DmaEvidence(), t.RecoveryEvidence())
    assert report.software_integrity == t.ASSESSED
    assert report.firmware_integrity == t.FIRMWARE_UNVERIFIED
    assert report.hardware_provenance == t.PROVENANCE_UNKNOWN
    assert report.platform_trusted is False


def test_unassessed_software_also_blocks_trust():
    report = clean_platform(software_assessed=False)
    assert report.software_integrity == t.UNASSESSED
    assert report.platform_trusted is False
    assert any("software integrity was not assessed" in b for b in report.blocking)


def test_absence_is_never_read_as_cleanliness():
    """Secure Boot enabled but signing unobserved: protect is unverified, not satisfied.

    Half of a requirement is not half a pass. The first test here is the one that matters: a
    single observed flag must not lift its requirement.
    """
    half = t.assess_platform(True, t.BootEvidence(secure_boot_enabled=True),
                             ATTESTED, GOOD_DMA, GOOD_RECOVERY)
    assert half.protect == t.FIRMWARE_UNVERIFIED
    assert half.detect == t.FIRMWARE_UNVERIFIED
    assert half.firmware_integrity == t.FIRMWARE_UNVERIFIED
    assert half.platform_trusted is False

    both = t.assess_firmware(t.BootEvidence(secure_boot_enabled=True, firmware_signed=True))
    assert both[0] == t.FIRMWARE_UNVERIFIED      # protect met, detect and recover not observed
    assert both[1] == t.FIRMWARE_ASSESSED


def test_a_failed_requirement_outranks_a_missing_one():
    boot = t.BootEvidence(True, True, False, True, True, True)
    firmware, protect, detect, recover = t.assess_firmware(boot)
    assert (protect, detect, recover) == (t.FIRMWARE_ASSESSED, t.FIRMWARE_FAILED, t.FIRMWARE_ASSESSED)
    assert firmware == t.FIRMWARE_FAILED
    assert any("requirement failed" in b for b in clean_platform(boot=boot).blocking)


# --- provenance ---------------------------------------------------------------------

def test_provenance_needs_digest_attestation_and_custody_together():
    assert t.assess_provenance(ATTESTED)[0] == t.PROVENANCE_VERIFIED
    partial = [t.Component("Dell", "R650", "SN1", "sha256:aa", True, None)]
    assert t.assess_provenance(partial)[0] == t.PROVENANCE_PARTIAL
    assert t.assess_provenance([t.Component("Unknown", "generic")])[0] == t.PROVENANCE_UNKNOWN
    assert t.assess_provenance([])[0] == t.PROVENANCE_UNKNOWN


def test_one_unknown_component_downgrades_the_aggregate():
    mixed = ATTESTED + [t.Component("Unknown", "add-in card")]
    state, rows = t.assess_provenance(mixed)
    assert state == t.PROVENANCE_PARTIAL
    assert [r["state"] for r in rows][-1] == t.PROVENANCE_UNKNOWN


# --- dma ----------------------------------------------------------------------------

def test_unknown_iommu_is_unverifiable_not_contained():
    assert t.assess_dma(t.DmaEvidence()) == t.DMA_UNVERIFIABLE


def test_explicitly_disabled_thunderbolt_security_is_exposed():
    assert t.assess_dma(t.DmaEvidence(True, "none", True, True)) == t.DMA_EXPOSED


def test_iommu_off_is_exposed_whatever_else_is_claimed():
    assert t.assess_dma(t.DmaEvidence(False, "secure", True, True)) == t.DMA_EXPOSED


def test_fully_mediated_ports_are_contained():
    assert t.assess_dma(t.DmaEvidence(True, "user", True, True)) == t.DMA_CONTAINED


def test_unrestricted_external_ports_stay_exposed():
    assert t.assess_dma(t.DmaEvidence(True, "dponly", True, False)) == t.DMA_EXPOSED


# --- recovery -----------------------------------------------------------------------

def test_recovery_needs_all_four_observations():
    assert t.assess_recovery(GOOD_RECOVERY) == t.RECOVERY_VALIDATED
    assert t.assess_recovery(t.RecoveryEvidence(True, True, True, None)) == t.RECOVERY_PARTIAL
    assert t.assess_recovery(t.RecoveryEvidence(True, False, True, True)) == t.RECOVERY_UNVALIDATED


def test_untested_recovery_blocks_trust_even_when_everything_else_passes():
    report = clean_platform(recovery=t.RecoveryEvidence(True, True, None, True))
    assert report.platform_trusted is False
    assert any("recovery" in b for b in report.blocking)


# --- the one case where trust is claimed --------------------------------------------

def test_every_axis_established_is_the_only_route_to_trusted():
    report = clean_platform()
    assert report.platform_trusted is True
    assert report.blocking == []
    json.dumps(report.as_dict())


def test_the_guard_rejects_a_trusted_claim_with_unknown_axes():
    forged = {"platform_trusted": True, "software_integrity": t.ASSESSED,
              "firmware_integrity": t.FIRMWARE_UNVERIFIED,
              "hardware_provenance": t.PROVENANCE_VERIFIED,
              "dma_exposure": t.DMA_CONTAINED, "recovery": t.RECOVERY_VALIDATED}
    try:
        t.assert_no_false_assurance(forged)
    except AssertionError as exc:
        assert "firmware_integrity" in str(exc)
    else:
        raise AssertionError("the false-assurance guard accepted a forged platform claim")


def test_no_assessment_ever_reaches_the_guard_violation():
    cases = [
        clean_platform(boot=t.BootEvidence()),
        clean_platform(components=[]),
        clean_platform(dma=t.DmaEvidence()),
        clean_platform(recovery=t.RecoveryEvidence()),
    ]
    for report in cases:
        assert report.platform_trusted is False
        t.assert_no_false_assurance(report.as_dict())


# --- reporting ----------------------------------------------------------------------

def test_every_report_carries_the_limits_of_the_method():
    report = clean_platform()
    assert len(report.limitations) >= 4
    assert any("implant" in l for l in report.limitations)
    assert any("side channel" in l for l in report.limitations)
    assert any("manufacturing" in l for l in report.limitations)


def test_rendered_output_separates_the_three_axes():
    text = t.render(clean_platform(boot=t.BootEvidence(secure_boot_enabled=True),
                                   components=[]))
    assert "software integrity : assessed" in text
    assert "firmware integrity : unverified" in text
    assert "provenance         : unknown" in text
    assert "platform trusted   : no" in text


def test_escalation_is_specific_to_what_is_missing():
    report = clean_platform(dma=t.DmaEvidence(True, "none", True, True), components=[])
    joined = " ".join(report.escalation)
    assert "port" in joined and "provenance" in joined
    assert len(set(report.escalation)) == len(report.escalation)


def test_the_module_does_not_touch_the_machine_it_assesses():
    import ast

    tree = ast.parse((HW / "trust.py").read_text())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    forbidden = {"subprocess", "os", "socket", "shutil", "ctypes", "platform"}
    assert imported & forbidden == set()
    calls = [n.func.id for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)]
    assert "open" not in calls


def test_cli_runs_as_a_process():
    import subprocess

    for flag in ([], ["--json"]):
        result = subprocess.run([sys.executable, str(HW / "trust.py"), *flag],
                                capture_output=True, text=True, timeout=120)
        assert result.returncode == 0, result.stderr[-300:]
        assert result.stdout.strip()

#!/usr/bin/env python3
"""Correlate what a sinkhole observed about the other end. Claim nothing it cannot support.

The report this produces answers one question: given the connection facts we actually hold, what
may be said about the infrastructure on the other side? Its most important field is the one that
never changes. `ownership: not established` is printed on every report, because an address in a
provider's range does not establish that the operator owns the account, controls the host, or is
even the person at the keyboard. A compromised customer instance, a shared NAT, a rented proxy and
a bulletproof host all look identical from here.

What the module may do: correlate observable connection metadata already recorded by the sinkhole
(address, ports, timestamps, reuse, TLS parameters), compare it against provider ranges it is given,
and state a hypothesis with its basis and its competing explanations.

What it may not do, and cannot, since it has no network code: query the provider, resolve reverse
DNS off-box, enumerate services on the source, use credentials seen in a session, or send anything
to the connecting party. Evidence preservation is a list of instructions for the operator, not
actions taken here.

    python harness/deception/aws_intel.py --facts '{"source_ip": "198.51.100.9", ...}'
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import sys
from dataclasses import asdict, dataclass, field

# Ordered strongest to weakest. Confidence is capped by the strongest evidence actually present,
# so a plausible-looking port set cannot lift a report on its own.
EVIDENCE_WEIGHT = {
    # An address in a provider's range is the weakest thing we can observe, not the strongest:
    # it says where the packets came from and nothing about who sent them. Reuse and TLS
    # parameters are harder to arrange by accident, so they carry the weight.
    "provider_range_match": 1,
    "reverse_dns_consistent_with_provider": 1,
    "nonstandard_c2_port": 1,
    "no_tls_offered": 1,
    "reuse_across_sessions": 2,
    "tls_fingerprint_matches_known_tool": 2,
}
CONFIDENCE = {0: "insufficient_evidence", 1: "low", 2: "moderate", 3: "elevated"}

AWS_PUBLIC_RANGES = ("3.0.0.0/8", "13.32.0.0/15", "18.128.0.0/9", "52.0.0.0/8", "54.0.0.0/8")

C2_PORTS = {4444, 1337, 31337, 9001, 12345, 5555, 6667}

PROHIBITED = [
    "access the provider account or console",
    "use credentials observed in a session",
    "scan, probe or connect to the source address",
    "attempt attribution beyond what the provider supplies on request",
    "retaliate in any form, including flooding or denial of the source",
]

PRESERVATION = [
    "hash the session transcript and store the digest with the session id",
    "record connection timestamps in UTC with the source port, not just the address",
    "retain TLS parameters (offered versions, cipher order, certificate bytes if any) verbatim",
    "retain the full command transcript with per-command timestamps",
    "keep the sinkhole's own configuration and image digest with the record",
    "store all of the above for the period the operator's policy requires before analysis",
]


@dataclass
class Facts:
    """Only what the sinkhole can see. Anything else has to be absent, not assumed."""

    source_ip: str
    source_ports: list[int] = field(default_factory=list)
    first_seen: str = ""
    last_seen: str = ""
    session_count: int = 1
    tls_offered: bool = True
    tls_fingerprint: str = ""
    reverse_dns: str = ""
    observed_services: list[str] = field(default_factory=list)


@dataclass
class Hypothesis:
    statement: str
    basis: list[str]
    confidence: str
    alternatives: list[str]


@dataclass
class Report:
    source: str
    provider_observed: str
    ownership: str
    infrastructure_role: str
    hypothesis: Hypothesis
    indicators: list[str]
    possible_exposed_services: list[str]
    reuse_evidence: list[str]
    confidence: str
    alternative_explanations: list[str]
    recommended_reporting: list[str]
    evidence_preservation: list[str]
    prohibited_actions: list[str]
    missing_information: list[str]
    limitations: list[str]
    record_digest: str = ""

    def as_dict(self) -> dict:
        return asdict(self)


def _in_aws(ip: str) -> str:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    for cidr in AWS_PUBLIC_RANGES:
        if addr in ipaddress.ip_network(cidr):
            return cidr
    return ""


def correlate(facts: Facts) -> Report:
    """Turn connection facts into a hypothesis and the reasons it may be wrong."""
    basis: list[str] = []
    weight = 0
    indicators: list[str] = []
    role = "unknown"
    provider = "unidentified"

    cidr = _in_aws(facts.source_ip)
    if cidr:
        provider = "Amazon Web Services (address space only)"
        basis.append(f"source address falls inside {cidr}, which is AWS public address space")
        weight = max(weight, EVIDENCE_WEIGHT["provider_range_match"])
        role = "address in provider space; instance, load balancer or relay indistinguishable from here"

    if facts.reverse_dns:
        looks_provider = any(token in facts.reverse_dns.lower()
                             for token in ("amazonaws", "compute", "ec2"))
        indicators.append(f"reverse DNS: {facts.reverse_dns}")
        if looks_provider:
            basis.append("reverse DNS is consistent with provider-assigned naming")
            weight = max(weight, EVIDENCE_WEIGHT["reverse_dns_consistent_with_provider"])
        else:
            basis.append("reverse DNS does not match provider naming, which may be a custom name")

    if facts.session_count > 1:
        basis.append(f"the same source appeared in {facts.session_count} sessions")
        weight = max(weight, EVIDENCE_WEIGHT["reuse_across_sessions"])

    if facts.tls_fingerprint:
        indicators.append(f"TLS fingerprint: {facts.tls_fingerprint}")
        weight = max(weight, EVIDENCE_WEIGHT["tls_fingerprint_matches_known_tool"])
        basis.append("TLS parameters were recorded and can be compared against known tool defaults")
    elif not facts.tls_offered:
        basis.append("the connection offered no TLS, which is common for raw reverse shells")
        weight = max(weight, EVIDENCE_WEIGHT["no_tls_offered"])

    c2 = [p for p in facts.source_ports if p in C2_PORTS]
    if c2:
        indicators.append(f"source ports associated with common tooling: {c2}")
        weight = max(weight, EVIDENCE_WEIGHT["nonstandard_c2_port"])
        basis.append("source ports are frequently reused defaults rather than ephemeral choices")

    indicators.extend(f"observed service: {s}" for s in facts.observed_services)

    missing = []
    if not facts.first_seen:
        missing.append("first observation timestamp")
    if not facts.tls_offered and not facts.tls_fingerprint:
        missing.append("TLS parameters (none offered, so nothing to compare)")
    if facts.session_count == 1:
        missing.append("a second session, which is what turns reuse into evidence")

    confidence = CONFIDENCE[min(weight, 3)]
    if not basis:
        confidence = "insufficient_evidence"

    alternatives = [
        "the address belongs to a compromised customer instance rather than the operator",
        "traffic arrived through a shared NAT, VPN exit or residential proxy",
        "the host is rented or resold infrastructure operated by someone else",
        "the address is a relay, and the operator is elsewhere",
    ]
    if provider == "unidentified":
        alternatives.insert(0, "the address space belongs to a provider not covered by the ranges supplied")

    statement = ("the connecting party used infrastructure in provider address space"
                 if cidr else "no provider attribution is supported by the evidence held")
    hypothesis = Hypothesis(statement=statement, basis=basis or ["no evidence sufficient to attribute"],
                           confidence=confidence, alternatives=alternatives)

    reporting = [
        "report to the provider's abuse contact with the session digest and timestamps, "
        "not with conclusions about ownership" if cidr else
        "report to the operator's national CERT or CSIRT with the session digest",
        "include the observed command classes and infrastructure reuse, which are the parts a "
        "provider can act on",
        "state explicitly that the report does not assert who operates the host",
    ]

    limitations = [
        "ownership is never established from an address; this report does not claim it",
        "no provider API, WHOIS, DNS resolution or active probe was performed by this module",
        "command content was not analysed for attribution and must not be, without a lawful basis",
    ]

    digest = hashlib.sha256(
        json.dumps({"source": facts.source_ip, "ports": sorted(facts.source_ports),
                    "first": facts.first_seen, "last": facts.last_seen,
                    "sessions": facts.session_count}, sort_keys=True).encode()).hexdigest()[:16]

    return Report(
        source=facts.source_ip, provider_observed=provider, ownership="not established",
        infrastructure_role=role, hypothesis=hypothesis, indicators=indicators,
        possible_exposed_services=sorted(set(facts.observed_services)) or ["none observed"],
        reuse_evidence=[f"{facts.session_count} session(s) from this source"] if facts.session_count > 1 else [],
        confidence=confidence, alternative_explanations=alternatives,
        recommended_reporting=reporting, evidence_preservation=PRESERVATION,
        prohibited_actions=PROHIBITED, missing_information=missing, limitations=limitations,
        record_digest=digest)


def render(report: Report) -> str:
    lines = [
        f"source            {report.source}",
        f"provider observed {report.provider_observed}",
        f"ownership         {report.ownership}",
        f"role              {report.infrastructure_role}",
        f"confidence        {report.confidence}",
        f"statement         {report.hypothesis.statement}",
        "basis:",
    ]
    lines += [f"  - {b}" for b in report.hypothesis.basis]
    lines.append("alternatives that fit the same evidence:")
    lines += [f"  - {a}" for a in report.alternative_explanations]
    lines.append("reporting:")
    lines += [f"  - {r}" for r in report.recommended_reporting]
    lines.append("prohibited:")
    lines += [f"  - {p}" for p in report.prohibited_actions]
    lines.append(f"digest            {report.record_digest}")
    return "\n".join(lines)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description="Report what the connection facts support.")
    parser.add_argument("--facts", help="JSON object with the connection facts")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    payload = json.loads(args.facts) if args.facts else {
        "source_ip": "52.14.203.77", "source_ports": [4444, 51233],
        "first_seen": "2026-11-08T20:04:11Z", "last_seen": "2026-11-08T21:19:02Z",
        "session_count": 3, "tls_offered": False, "reverse_dns": "ec2-52-14-203-77.compute-1.amazonaws.com",
        "observed_services": ["reverse_shell_attempt", "secret_file"]}
    report = correlate(Facts(**payload))
    print(json.dumps(report.as_dict(), indent=2, sort_keys=True) if args.json else render(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

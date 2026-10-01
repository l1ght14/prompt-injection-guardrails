"""The policy layer: turns a trust classification into a capability ceiling.

Everything security-critical in this project converges here. The rule is short enough to
audit in one sitting, which is the point:

    While UNTRUSTED content is in scope, the ceiling is Risk.SCORE.
    That permits reading and scoring, and refuses every external write.

An agent that has read a malicious resume and believes, in its own generated text, that it
should email the attacker, calls `email`. The router asks the grant. The grant says no. The
document's opinion is not consulted, because it was never an input to the decision.

The detection rules in `isolate.py` deliberately do NOT feed this. If they did, the ceiling
would depend on a regex beating an attacker, which is the assumption this project exists to
refute. Classification affects *reporting and the audit trail*, and the ceiling is fixed by
context instead. That is why a brand-new injection technique with no matching rule is still
fully contained: it lands in the same UNTRUSTED bucket as everything else.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..tools.base import Grant, Risk

from .isolate import Finding, Trust


@dataclass
class Decision:
    """Why the agent may or may not do something, recorded for the log."""

    allowed: bool
    rule: str
    detail: str
    ceiling: Risk

    def to_dict(self) -> dict:
        return {
            "allowed": self.allowed,
            "rule": self.rule,
            "detail": self.detail,
            "ceiling": self.ceiling.value,
        }


# What a context is allowed to reach. The key is the trust level, and the value is the
# ceiling that applies while that trust is in scope.
CEILINGS: dict[Trust, Risk] = {
    # An untrusted document is being read. Reading and scoring are fine; anything that
    # reaches outside the system is not available, regardless of what the model concludes.
    Trust.UNTRUSTED: Risk.SCORE,
    # Trusted context only after a human or the system itself established it. Even here,
    # irreversible actions need a separate confirmation token.
    Trust.TRUSTED: Risk.IRREVERSIBLE,
}

REASON = {
    Trust.UNTRUSTED: "untrusted third-party content is in scope",
    Trust.TRUSTED: "system-authored context",
}


@dataclass
class Policy:
    """Holds the current trust posture and issues grants."""

    trust: Trust = Trust.UNTRUSTED
    findings: list[Finding] = field(default_factory=list)
    # Rules that fired, in order, deduplicated. Every block in the log points at one of these
    # or at a capability rule, which is the ship gate's "every block traceable to a rule".
    fired_rules: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        for f in self.findings:
            self.note_rule(f.rule)

    def note_rule(self, rule: str) -> None:
        if rule not in self.fired_rules:
            self.fired_rules.append(rule)

    def grant_for(self, trust: Trust | None = None) -> Grant:
        t = trust or self.trust
        return Grant(ceiling=CEILINGS[t], reason=REASON[t])

    def promote_to_trusted(self, reason: str) -> None:
        """Explicit trust promotion.

        There is deliberately no content-driven promotion path. Raising the ceiling is a
        decision someone makes, with a reason, and the reason goes in the log.
        """
        if not reason:
            raise ValueError("trust promotion requires a recorded reason")
        self.trust = Trust.TRUSTED
        self.note_rule("TRUST_PROMOTED")

    def demote_to_untrusted(self) -> None:
        self.trust = Trust.UNTRUSTED

    def rules_fired(self) -> list[str]:
        return list(self.fired_rules)


def evaluate_output(text: str, ceiling: Risk) -> Decision:
    """Output scanning: what the agent produced, as opposed to what it consumed.

    Deliberately narrow. Output can leak what went in, and it can contain a payload aimed at
    whatever reads it next - here, the ATS, and later, a human. It cannot cause an action by
    itself, so this returns a decision and a rule rather than trying to sanitise prose. A
    filter that rewrites model output is a filter that will corrupt legitimate output
    eventually, and the capability ceiling is the control that matters.
    """
    from .isolate import scan

    findings = scan(text)
    if not findings:
        return Decision(True, "OUTPUT_CLEAN", "no instruction-shaped content in output",
                        ceiling)
    # Exfiltration and authority spoofing in the output are the two that matter: the first
    # leaks, the second deceives a downstream human reader.
    priority = ("secret_exfiltration", "config_disclosure", "authority_spoof",
                "delimiter_breakout")
    rule = next((p for p in priority if any(f.rule == p for f in findings)), findings[0].rule)
    return Decision(
        False,
        rule,
        f"output contains instruction-shaped content: "
        f"{', '.join(sorted({f.rule for f in findings}))}",
        ceiling,
    )

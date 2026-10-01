"""Tools, their risk levels, and the capability grant that decides which are callable.

This module is the project's thesis in code. The claim being demonstrated is that filtering
injection *text* is theatre, and that the control that actually matters is restricting what
the agent is permitted to do once it has been fooled. So the enforcement point is here, at
the tool boundary, and it is a property of the caller's situation rather than of the content.

The distinction that makes this work:

    "This resume says to email the attacker"     -> a string. Blocklisting it is a losing game.
    "We are currently processing untrusted input" -> a fact about the caller.

The first is attacker-controlled and infinitely variable. The second is held by the harness,
cannot be changed by anything the document says, and admits a total rule: while untrusted
content is in scope, irreversible tools are not callable at all. There is no phrasing of an
injection that gets past it, because the injection never gets a vote.

`ToolRegistry.call` is the only path to a tool. It takes a `CapabilityGrant` and refuses
anything the grant does not cover, *before* the tool body runs. An agent that has been fully
convinced by its document still cannot reach `email` or `ats_write` from inside that document,
because the grant - not the model's judgement - is what is checked.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Risk(str, Enum):
    """What a tool can do if it runs unattended."""

    READ = "read"  # returns data, changes nothing
    SCORE = "score"  # writes an internal, reversible evaluation
    EXTERNAL_WRITE = "external_write"  # visible outside the sandbox: ATS, database
    IRREVERSIBLE = "irreversible"  # cannot be undone: sends email, cancels a booking


# Ordered least to most dangerous. A grant is a ceiling, so comparisons use this order and a
# tool is allowed if its own level is at or below the ceiling.
_ORDER = {Risk.READ: 0, Risk.SCORE: 1, Risk.EXTERNAL_WRITE: 2, Risk.IRREVERSIBLE: 3}


@dataclass(frozen=True)
class ToolSpec:
    name: str
    risk: Risk
    description: str
    # Irreversible tools additionally require an explicit human confirmation token. This is a
    # second, independent control: even with a grant wide enough to call the tool, the call
    # is refused without a token that only a human step can produce.
    requires_confirmation: bool = False
    # Tools whose arguments are a judgement (a score, a status decision). Their arguments are
    # refused when the value appears in the untrusted text. The capability ceiling bounds
    # which tool may run and says nothing about whether the agent may believe a value the
    # document supplied, so this is a genuinely separate control rather than a stricter
    # version of the same one.
    rejects_untrusted_values: bool = False


@dataclass
class Grant:
    """What the agent may do in the current context, and why.

    `ceiling` is the maximum risk level callable. `reason` is recorded in every block log so
    a refusal can be explained after the fact without guessing.

    A `None` token means no human confirmation is available, which is the default when
    processing untrusted input.

    `untrusted_text` is here so the router can police *value provenance*. The capability
    ceiling answers "may this tool run?"; it cannot answer "may this tool be handed a number
    the attacker typed?" Blocking `score_candidate` outright would break the product's actual
    job, but persisting a score lifted verbatim from the document is exactly the manipulation
    the threat model is about. Keeping both facts in one object means all enforcement stays at
    the single choke point rather than spreading into callers who can forget it.
    """

    ceiling: Risk = Risk.READ
    reason: str = "default: least privilege"
    confirmation_token: str | None = None
    allowed: set[str] = field(default_factory=set)
    untrusted_text: str = ""

    def permits(self, tool: ToolSpec) -> tuple[bool, str]:
        """May this tool be called? Returns (allowed, reason_if_not)."""
        if tool.name in self.allowed:
            return True, "explicitly allowed"
        if _ORDER[tool.risk] <= _ORDER[self.ceiling]:
            return True, f"risk {tool.risk.value} <= ceiling {self.ceiling.value}"
        return False, (
            f"tool '{tool.name}' is {tool.risk.value} but this context's ceiling is "
            f"{self.ceiling.value} ({self.reason})"
        )

    def value_is_attacker_supplied(self, value: object) -> bool:
        """Did this value come out of the untrusted document?

        A substring check, deliberately crude. It cannot tell an attacker-chosen 100 from an
        agent-computed 100 that happens to appear in a resume listing "scored 100 on a
        take-home", and it is not trying to. It only asks whether this exact string was
        available to be copied, which is enough to require a second look.
        """
        if not self.untrusted_text or not isinstance(value, (str, int, float)):
            return False
        return str(value).strip().lower() in self.untrusted_text.lower()


class ToolDenied(Exception):
    """Raised when the capability gate refuses a call.

    Carries the rule id that fired so the block is traceable to a named rule in the log -
    one of the project's ship-gate requirements. The id is also in the message text, because
    a log line that only exists in a structured field is a log line nobody reads when they
    are staring at a stack trace.
    """

    def __init__(self, rule: str, message: str, tool: str) -> None:
        super().__init__(f"[{rule}] {message}")
        self.rule = rule
        self.tool = tool
        self.reason = message


@dataclass
class CallResult:
    tool: str
    ok: bool
    value: Any = None
    rule: str | None = None
    detail: str = ""


class ToolRegistry:
    """Holds the tools and is the single choke point for calling them."""

    def __init__(self) -> None:
        self._tools: dict[str, ToolSpec] = {}
        self._impls: dict[str, Callable[..., Any]] = {}
        self.calls: list[dict] = []  # audit log; see record()

    def register(self, spec: ToolSpec, impl: Callable[..., Any]) -> None:
        if spec.name in self._tools:
            raise ValueError(f"tool {spec.name!r} already registered")
        self._tools[spec.name] = spec
        self._impls[spec.name] = impl

    def get(self, name: str) -> ToolSpec:
        if name not in self._tools:
            raise KeyError(f"unknown tool {name!r}; have {sorted(self._tools)}")
        return self._tools[name]

    def names(self) -> list[str]:
        return sorted(self._tools)

    def call(self, name: str, grant: Grant, **kwargs) -> CallResult:
        """The only path to a tool. Refuses before invoking anything.

        Three independent refusals live here, deliberately: the per-context allowlist, the
        risk ceiling, and human confirmation for irreversible tools. Any one of them is
        sufficient to stop the call, so a mistake in one is not a bypass.
        """
        spec = self.get(name)

        if spec.name not in grant.allowed and _ORDER[spec.risk] > _ORDER[grant.ceiling]:
            self.record(name, False, "CAPABILITY_DENIED", grant.reason)
            raise ToolDenied(
                "CAPABILITY_DENIED",
                f"tool '{name}' is {spec.risk.value} but this context's ceiling is "
                f"{grant.ceiling.value} ({grant.reason})",
                name,
            )

        if spec.requires_confirmation and not grant.confirmation_token:
            self.record(name, False, "CONFIRMATION_REQUIRED", spec.description)
            raise ToolDenied(
                "CONFIRMATION_REQUIRED",
                f"tool '{name}' is irreversible and needs a human confirmation token",
                name,
            )

        if spec.rejects_untrusted_values:
            supplied = sorted(
                f"{k}={v!r}" for k, v in kwargs.items()
                if k != "candidate_id" and grant.value_is_attacker_supplied(v)
            )
            if supplied:
                detail = f"argument value taken from untrusted content: {', '.join(supplied)}"
                self.record(name, False, "UNTRUSTED_VALUE_PROVENANCE", detail)
                raise ToolDenied("UNTRUSTED_VALUE_PROVENANCE", detail, name)

        try:
            value = self._impls[name](**kwargs)
        except Exception as exc:  # noqa: BLE001 - a tool must not be able to crash the router
            self.record(name, False, "TOOL_ERROR", str(exc)[:200])
            return CallResult(tool=name, ok=False, rule="TOOL_ERROR", detail=str(exc)[:200])
        self.record(name, True, "OK", "")
        return CallResult(tool=name, ok=True, value=value)

    def record(self, tool: str, allowed: bool, rule: str, detail: str) -> None:
        self.calls.append({"tool": tool, "allowed": allowed, "rule": rule, "detail": detail})

    def blocks(self) -> list[dict]:
        return [c for c in self.calls if not c["allowed"]]

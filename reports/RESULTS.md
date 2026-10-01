# Doorman - prompt injection guardrails: results

## Headline

Attack success rate across 60 hand-written attacks: **0.8667 undefended -> 0.0000 with guardrails.**

False positive rate on 100 benign resumes: **0.0000**.

Decider: **simulated worst-case adversary**. The simulated decider is a worst-case adversary that obeys whatever the document tells it. The number above is therefore an upper bound on exposure for an agent that has already been fully defeated, not a prediction of how often a real model is defeated. Measuring that requires `--decider llm` and a key.

## By attack family

| attack family | n | ASR before | ASR after | containment | inert |
|---|---|---|---|---|---|
| `authority_spoof` | 6 | 0.6667 | 0.0000 | 1.0000 | 2 |
| `direct_override` | 8 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `encoded` | 9 | 0.3333 | 0.0000 | 1.0000 | 6 |
| `exfiltration` | 7 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `indirect_tool_result` | 7 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `metadata` | 7 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `nested` | 7 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `social` | 9 | 1.0000 | 0.0000 | 1.0000 | 0 |

## Three outcomes, not two

| | undefended | guarded |
|---|---|---|
| executed (attack worked) | 52 | 0 |
| blocked (a named rule refused it) | 0 | 52 |
| inert (never attempted) | 8 | 8 |

Containment is computed over attempts only: **1.0000** of the 52 attempts were blocked.

**8 attacks are inert and are not credited to the guardrails.** They are counted against the attack success rate, but nothing blocked them: the regex-based simulator never parsed the payload, so it never formed an intent. A base64 string is not a command until something can read it.

This is the measurement's own blind spot rather than a property of the defence, and it is the reason the report does not simply claim a 0% success rate over 60 attacks. Run `--decider llm` with a key to measure what a model actually does with these.


## Bypasses found and closed

### delimiter breakout

- **Layer defeated:** hard isolation (layer 2)
- **payload closed tag:** True
- **escaped nonce wrapper:** False
- **succeeded unguarded:** True
- **succeeded guarded:** False
- **closed by:** per-call nonce in the isolation tag; the wrapper does not terminate on a guessed tag
- **residual risk:** none for this bypass. The payload cannot learn the nonce, and a document that guessed it would stay inside the block.

### score laundering

- **Layer defeated:** capability ceiling (layer 3) - by design, not by defect
- **succeeded with capability only:** True
- **succeeded with provenance check:** False
- **agent computed score still works:** True
- **closed by:** UNTRUSTED_VALUE_PROVENANCE: a judgement argument that appears verbatim in the untrusted text is refused, while the same tool with an agent-computed value still succeeds
- **residual risk:** the check is a substring test. A payload that encodes the number obfuscated, or instructs the agent in prose rather than supplying a literal, would not match it. The capability ceiling still holds, so the blast radius stays at one internal, reversible field.

### confirmation token as an accidental baseline control

- **Layer defeated:** the measurement itself
- **baseline succeeded before fix:** False
- **baseline succeeded after fix:** True
- **closed by:** the undefended arm now grants a confirmation token, so 'unguarded' means no controls rather than 'every control except one'
- **residual risk:** none, but it is the reason this project's baseline is 0.87 and not the 0.53 an earlier version reported.

## Reading these numbers honestly

- `score_candidate` is deliberately inside the untrusted ceiling, because refusing to score would mean refusing to do the job. The defence there is a provenance check on the *value*, not a tighter ceiling. The two bypass entries above show both that it blocks the attacker-chosen score and that an agent-computed score still passes.
- A 0.0000 attack success rate means no attack reached a forbidden tool in this corpus, with this adversary. It is not a claim that the system is secure.
- The rules in `src/guard/isolate.py` drive reporting, not the ceiling. A brand-new injection technique with no matching rule lands in the same UNTRUSTED bucket as everything else and is contained by the same capability grant.

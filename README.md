# Doorman — prompt injection guardrails for an agent whose input is hostile by design

A recruiting agent reads candidate resumes and portfolio PDFs, scores them, emails candidates
and writes back to an ATS. Every document it reads was written by someone with a direct
incentive to manipulate the outcome.

The thesis this project is built to demonstrate: **filtering the phrase "ignore previous
instructions" is theatre.** The control that matters is limiting what the agent is allowed to
do *after* it has been fooled.

---

## Headline

60 hand-written attacks, 8 families, over a 57,000-document-free but fully instrumented
agent. 100 benign resumes for the false-positive rate.

| | undefended | with guardrails |
|---|---|---|
| Attack success rate | **0.8667** | **0.0000** |
| False positive rate (benign resumes) | — | **0.0000** |
| Containment of attempted attacks | — | **1.0000** |

| attack family | n | ASR before | ASR after | containment | inert |
|---|---|---|---|---|---|
| `direct_override` | 8 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `metadata` | 7 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `indirect_tool_result` | 7 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `exfiltration` | 7 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `nested` | 6 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `social` | 9 | 1.0000 | 0.0000 | 1.0000 | 0 |
| `authority_spoof` | 6 | 0.6667 | 0.0000 | 1.0000 | 2 |
| `encoded` | 9 | 0.3333 | 0.0000 | 1.0000 | 6 |

### Read the "inert" column before quoting the 0.0000

8 attacks were **not blocked** — they were *never attempted*. The regex-based adversary could
not parse a base64 payload, so it never formed an intent and nothing was refused. They count
against the attack success rate but are **not credited to the guardrails**, and containment is
therefore computed over attempts only.

This is the measurement's blind spot, not a property of the defence. It is the reason the
report does not simply say "0% success across 60 attacks". Run `--decider llm` with a key to
find out what a model actually does with those.

---

## Architecture

Five layers, in the order they appear in the request path.

```
1. input classification   scan()      -> which rules fired, for the audit trail
2. hard isolation         isolate()   -> nonce-tagged <untrusted_document> block
3. per-context allowlist  Grant       -> ceiling = Risk.SCORE while untrusted is in scope
4. confirmation           Grant       -> irreversible tools need a human token
5. output scanning        evaluate_output()
```

**Layers 1 and 5 do not set the ceiling.** That is the whole point. If the ceiling depended on
a regex beating an attacker, the control would inherit the regex's blind spots — and a
brand-new injection technique with no matching rule would land in a *different, more trusted*
bucket. Here it lands in the same UNTRUSTED bucket as everything else.

The distinction that makes the design work:

```
"This resume says to email the attacker"      -> a string. Blocklisting it is a losing game.
"We are currently processing untrusted input"  -> a fact about the caller.
```

The first is attacker-controlled and infinitely variable. The second is held by the harness,
cannot be changed by anything the document says, and admits a total rule.

### The capability ceiling

```
while UNTRUSTED content is in scope:   ceiling = Risk.SCORE
```

That permits `read_resume` and `score_candidate`, and refuses `ats_write` and `send_email`.
An agent that has read a malicious resume and genuinely believes it should email the attacker
calls `email`, the router asks the grant, and the grant says no. The document's opinion is
never consulted, because it was never an input to the decision.

---

## Findings

**1. Score laundering defeated the capability layer, and the ceiling was right anyway.**
`score_candidate` is `Risk.SCORE` — exactly what the untrusted ceiling permits, because
refusing to score would mean refusing to do the job. 7 of 60 attacks set the candidate's own
score and succeeded.

Blocking the tool was never the answer. The fix is a *different* control: a judgement
argument that appears verbatim in the untrusted text is refused
(`UNTRUSTED_VALUE_PROVENANCE`). The capability ceiling bounds which tool may run; it says
nothing about whether the agent may believe a number the document supplied. `eval/bypass.py`
shows both halves — the attacker-chosen score is blocked and an agent-computed score of 42
still passes.

**2. My first baseline was flattering, and I only noticed by checking.** The undefended arm
still required a confirmation token for `send_email`, so every email-targeting attack scored
0.0000 *before any guardrail existed*. The headline improvement was measuring the harness
rather than the defence. With the baseline genuinely uncontrolled it went from 0.53 to **0.87**.

**3. The delimiter breakout was real, and the fix is structural.** Untrusted text that closed
the isolation tag and continued as if outside it was a complete escape against a fixed tag.
The tag now carries a per-call nonce the payload cannot learn, and a document that guesses it
stays inside the block rather than terminating it.

**4. Blocklists lose; a ceiling doesn't.** No rule in `guard/isolate.py` is load-bearing for
containment. Delete every pattern and the containment rate is unchanged, because the ceiling
never consulted them. That is the design working, not a redundancy — but it also means the
detection rules earn their place by improving the *audit trail*, not by preventing anything.

---

## What was wrong along the way

- The `delimiter_breakout` regex matched `</untrusted>` but not `</untrusted_document>` — the
  rule that exists specifically to catch the breakout, matching nothing. Caught by a test.
- The zero-width character class was written as literal characters and lost them passing
  through a shell, so it matched nothing. A security rule that matches nothing always passes.
- `ToolDenied` put the rule id only on the exception attribute, so a stack trace showed a
  refusal with no rule name — and one of the ship-gate requirements is that every block is
  traceable.
- The benign corpus sampled trap phrasings at random, so two of eleven never appeared in the
  100 documents and the false-positive rate was measured against a corpus that silently did
  not exercise the cases most likely to over-match.
- The simulated decider initially fired only on the literal string `call <tool>`, so the
  undefended baseline succeeded on 20% of the corpus. An evaluation whose baseline is an
  artefact of its own regex proves nothing.
- `--decider llm` without a key originally fell back to the offline mock, which answers
  `{"tool": null}` for everything and would have reported a perfect 0.0000 in *both* arms. It
  now refuses to run.

---

## Running it

```bash
pip install -r requirements.txt

python eval/redteam.py                 # ASR before/after by family, FPR on 100 resumes
python eval/bypass.py                  # the three bypasses, as executable evidence
python eval/report.py                  # RESULTS.md
python eval/report.py --check-only     # exit 1 if any claim disagrees with the data
pytest                                 # 70 tests, 92% coverage

# optional: measure against a real model instead of the worst-case adversary
$env:GROQ_API_KEY = "..."
python eval/redteam.py --decider llm
```

No key is needed for anything except the last command. The capability layer, the router, the
corpus and the full test suite run with no network and no spend.

---

## Structure

```
src/
  tools/base.py     ToolSpec, Grant, Risk, ToolRegistry.call  <- all enforcement, one function
  tools/impl.py     read_resume / score_candidate / ats_write / send_email
  guard/isolate.py  classification, unicode folding, nonce-tagged isolation
  guard/policy.py   trust -> ceiling; output scanning
  guard/llm.py      optional Groq/Gemini client (cached, retrying, key-safe)
  agent/loop.py     the agent, the deciders, and the run record
corpus/attacks.py   60 attacks, 8 families + 100 benign resumes
eval/redteam.py     the ship-gate measurement
eval/bypass.py      bypasses found and closed, as runnable evidence
eval/report.py      RESULTS.md + the consistency check
tests/              70 tests
```

## Ship gate

| requirement | status |
|---|---|
| ASR before and after, by attack family | `reports/RESULTS.md`, `reports/redteam.json` |
| FPR on 100 benign resumes, reported alongside | 0.0000 |
| One documented bypass found and closed | three, in `eval/bypass.py` |
| Every block traceable to a rule | asserted in tests and checked by `report.py` |

## Limitations

- **The adversary is a regex.** It reads plain-text imperatives. That is a reasonable worst
  case for the *guardrails*, and a poor model of model behaviour. 8 attacks defeat it and are
  reported as unattempted rather than contained.
- **8 of 60 attacks are unmeasured in practice.** Only `--decider llm` closes this, and that
  needs a key.
- **Containment is 1.0000 over this corpus.** That is not a claim that the system is secure.
  The corpus is mine, so it contains what I thought of; a real adversary reads the source.
- **The provenance check is a substring test.** A payload that obfuscates the number, or
  instructs in prose rather than supplying a literal, will not match it. The capability
  ceiling still holds, so the blast radius stays at one internal, reversible field.
- **No adversarial training.** The model is never fine-tuned to resist injection; the claim is
  that you do not need it to be when the ceiling holds.

## Licence

Code: MIT. No third-party datasets — the 60 attacks and 100 benign resumes are written here.

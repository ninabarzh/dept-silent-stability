# Custom correlation engines (educational)

*Observational contraptions for drawing patterns from the chaos of RPKI and BGP logs*

In Ankh-Morpork, if you wait long enough, even a drunken piper produces a tune — you just need someone to notice it. These scripts are precisely that: observers with a tendency to raise an eyebrow when the ordinary mutates into the bizarre.

They live in `anvil/correlation-engines` and do two things:

- watch how routing and validation behave over time,
- and whisper (or occasionally shout) when something looks decidedly odd.

They are referenced on the [Red Lantern simulation platform documentation](https://blue.tymyrddin.dev/docs/shadows/red-lantern/correlation/platforms).  

---

## What’s here

### `temporal-correlation.py`  

**BGPAttackCorrelator**

This script is a rule-based correlator that watches a stream of log lines for patterns that look like a BGP hijack — because sometimes the only difference between normal network chatter and an attack is the sequence and timing.

**In plain terms:**
- It parses syslog-style lines into structured events.
- It classifies events into types (suspicious login, ROA requests, validator syncs, etc.).
- It groups events by IP prefix.
- It looks for **attack patterns**, such as:
  - fraudulent ROA creation followed by publication,
  - suspicious login immediately before a ROA request,
  - multiple validators accepting the dodgy route.
- It outputs a correlation object with severity (`low`, `medium`, `high`, `critical`) and a human-friendly description.

**Philosophy:**  
“Look not only at what happened, but at *when* and *in what order*.”  
If Vimes had a log parser, this would be it.

---

### `time-series-anomaly-detection.py`  
**RPKIAnomalyDetector**

This is the statistics-friendly cousin who squints at numbers until they confess.

**What it does:**
- Keeps a rolling history of validation outcomes per prefix.
- Computes a baseline ratio of valid to invalid observations.
- For each new observation, calculates whether current behaviour is *anomalous*:
  - **3-sigma excursions** in valid/invalid ratio;
  - sudden validator consensus where previously there was none.
- Returns `(True, description)` if something looks statistically unusual, or `(False, reason)` if not.

**Key points:**
- Needs at least 10 past samples to create a sensible baseline.
- Uses simple z-score logic — no black magic, just old-fashioned statistics Ponder Stibbons might approve of over tea.

---

## Inputs and outputs

Both engines assume you feed them **structured input** at runtime:

- `BGPAttackCorrelator` expects lines of logs with timestamps and meaningful messages.
- `RPKIAnomalyDetector` expects counts of valid/invalid validations plus a timestamp.

Outputs are plain data structures or tuples indicating:
- whether something suspicious was detected,
- a description,
- and, in the case of the correlator, a severity score.

These are not sails to catch every wind; they are lanterns to illuminate suspicious ripples in the dark.

---

## Usage patterns

Use these where you need:

- detection of *sequences*, not just individual blips,
- statistical perspective on validation patterns,
- easy hooks into alerting or dashboards.

They are meant as **engines**, not polished UIs. You will want:

- a scheduler or runner to feed them events,
- a logger or sink to record their outputs,
- and perhaps a mug of tea while watching the world through their output.

---

## Style and assumptions

In keeping with the best traditions of the Watch:
- explicit rule sets over inscrutable black boxes,
- human-readable descriptions over mystic incantations,
- suspicion as the default position.

These scripts assume chaos; they simply try to notice when the chaos stops looking normal.

---

## Examples

See the `__main__` block in `temporal-correlation.py` for a sample log playbook that simulates:
- a login from an attacker,
- fraudulent route object creation,
- publication and validator syncs.

It produces a correlated “attack detected” report.

For anomaly detection, feed validation counts repeatedly and watch for sudden jumps or consensus shifts.

---

*“We do not merely watch the shadows, we dare to name them.”*



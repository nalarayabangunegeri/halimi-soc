# ADR-004 — AI is advisory and outside the detection path

**Status:** Accepted
**Date:** 2026-09-27

## Context

An LLM can summarise an incident and explain evidence faster than an analyst can
read raw logs. The same model will also confidently invent details, and its
input is untrusted telemetry that may contain adversarial instructions.

## Decision

AI output is advisory only. Detection, correlation, severity and authorization
are computed without it, and the system functions fully when no AI provider is
configured.

## Alternatives considered

- **AI-assisted detection.** Rejected: a probabilistic component in the
  detection path makes an alert impossible to reproduce or explain, which
  destroys the audit story the product is built on.
- **AI-suggested severity.** Rejected: severity drives triage priority. A model
  that can raise it can also be manipulated into raising it.
- **AI with tool access to the host.** Rejected outright for the MVP.

## Consequences

- Every alert and incident is explainable without an LLM.
- Provider failure degrades exactly one feature.
- AI output must be schema-validated and its evidence references resolved
  against application-owned records before it is displayed.

## Security impact

Telemetry is treated as data, never as instructions. Prompt injection is a
tested regression class rather than a theoretical concern, and the model cannot
change authorization, severity or response state.

## Revisit conditions

Revisit only for bounded, human-approved response actions, and only with an
independent authorization step between the model's recommendation and the
action.

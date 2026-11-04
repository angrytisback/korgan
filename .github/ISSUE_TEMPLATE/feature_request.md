---
name: Feature request
about: Propose a new capability or improvement
title: "feat: "
labels: enhancement
assignees: ""
---

## Problem

<!-- What problem are you trying to solve? Who is affected? Describe the use case, not the solution. -->

## Proposed Architecture Solution

<!-- Describe how this fits Korgan's Hexagonal Architecture. -->

- **Domain** (entities, value objects, errors; no I/O):
- **Ports** (new or changed traits):
- **Application** (use cases / orchestration; no `axum`/`sqlx`):
- **Adapters** (inbound HTTP and/or outbound Postgres, Redis, crypto, etc.):
- **Migrations / config changes** (if any):

## Security Considerations

<!-- Impact on tokens, secrets, enumeration, auditing, rate limiting, etc. -->

## Alternatives Considered

<!-- Other approaches and why they were rejected. -->

## Additional Context

<!-- Links, specs (RFCs), prior art. -->

# ADR 0002: Token Refresh Concurrency Managed Through Keycloak Configuration

- Status: ACCEPTED
- Date: 2026-11-10
- Reference: [CELDEV-1366](https://synjira.atlassian.net/browse/CELDEV-1366)

## Context

Cookie-authenticated requests must continue after the access cookie expires while
the refresh token remains valid. Concurrent browser requests can arrive with the
same refresh cookie before any response has replaced it. Multiple application
instances can also process these requests independently.

Strict refresh-token rotation can reject overlapping exchanges or leave the
browser holding a token from a response that completed out of order.

## Decision

Concurrent requests may independently exchange the same refresh token. The
application does not serialize refreshes, deduplicate exchanges, or share refresh
results. Deployments must configure Keycloak to tolerate refresh-token reuse.

- Disabling **Revoke Refresh Token** is the simplest mitigation.
- If revocation remains enabled, **Refresh Token Max Reuse** must be selected and
  tested for the deployed Keycloak version. Bounded reuse does not guarantee that
  every race succeeds.
- Verify overlapping requests and subsequent requests with the cookies actually
  retained by the browser in the target deployment.

This decision documents a deployment requirement. It does not assert that any
production configuration has been verified or changed.

## Consequences

- Refresh-token reuse weakens stolen-token replay protection compared with
  strict rotation.
- Realm-level configuration changes affect all clients in the realm.
- The refresh implementation remains stateless across application instances.
- Application-level coordination should be reconsidered if strict rotation
  becomes mandatory or concurrency failures remain unacceptable.

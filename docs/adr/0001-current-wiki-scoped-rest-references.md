# ADR 0001: Current-Wiki-Scoped REST References

- Status: accepted
- Date: 2026-07-30

## Context

Celements REST endpoints may accept XWiki document and space references. A
wiki-qualified reference can cross a tenant boundary, even when its qualifier
names the wiki currently handling the request. Accepting such references
without an explicit cross-wiki authorization and information-disclosure
contract risks exposing the existence or content of resources outside the
endpoint's intended scope.

REST responses also need one stable representation of references. Returning
wiki-qualified and local references interchangeably would make contracts
caller- and deployment-dependent.

## Decision

REST endpoints scoped to the wiki handling the request accept only canonical
local document and space references.

- Reject malformed, noncanonical, or wiki-qualified input references.
- Reject a wiki-qualified input even when its qualifier names the current wiki.
- Serialize response references canonically and locally.
- Treat a syntactically valid local reference with no visible result according
  to the endpoint's resource contract; do not infer a cross-wiki lookup.
- Do not reveal whether a rejected or inaccessible cross-wiki resource exists.

An endpoint that needs cross-wiki access must define a separate contract. That
contract must explicitly cover authorization, tenant boundaries, reference
serialization, and information disclosure before implementation.

## Consequences

- Current-wiki endpoints have an unambiguous tenant boundary.
- Clients cannot use a current-wiki endpoint as a cross-wiki discovery
  mechanism.
- Request validation must distinguish canonical local references from malformed,
  noncanonical, and wiki-qualified input.
- Responses remain portable because their references do not depend on the
  current wiki name.
- Cross-wiki use cases require deliberate API design rather than an implicit
  extension of a local endpoint.

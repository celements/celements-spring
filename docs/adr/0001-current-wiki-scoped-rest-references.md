# ADR 0001: Current-Wiki-Scoped REST References

- Status: accepted
- Date: 2026-07-30

## Context

Celements REST endpoints may accept XWiki document and space references. For an
endpoint scoped to the wiki handling the request, the request context already
defines the tenant boundary. A wiki qualifier introduces a second scope
selector: naming another wiki conflicts with the endpoint's scope, while naming
the current wiki creates an alternative representation and makes a
deployment-specific wiki name part of the public contract.

Requests and responses need one stable representation of references. Supporting
both qualified and local forms would make the contract caller-dependent, while
returning qualified references would make it deployment-dependent. Exposing or
accepting a cross-wiki scope requires an explicit authorization and
information-disclosure contract.

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

- Clients holding qualified references, including references qualified with the
  current wiki, must serialize them locally before calling these endpoints.
- Response references are contextual identifiers for the wiki serving the
  response, not globally unique identifiers. A client moving them between
  request contexts must retain the source-wiki context separately.
- Payloads neither expose nor depend on internal wiki names, so the same local
  reference representation can be used in deployments with different wiki
  names.
- Validation can reject every qualifier uniformly without comparing a supplied
  wiki name with the current wiki or disclosing whether it matched.
- Cross-wiki clients need a separate API contract with a public tenant identity,
  authorization rules, and defined disclosure behavior.

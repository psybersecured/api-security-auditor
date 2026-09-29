# Security Test Model

The project intentionally implements a bounded subset of API security automation suitable for a defensive academic project.

## Authentication

**Signal:** an operation marked secured in OpenAPI still returns 2xx when the `Authorization` header is removed or replaced with a clearly invalid token.

**Interpretation:** high-severity evidence for a likely authentication enforcement problem, but still validate whether the OpenAPI security declaration is accurate.

## Object-level authorization (BOLA)

**Signal:** a user-supplied alternate object identifier also returns 2xx.

**Why operator-supplied IDs?** Blind enumeration is intentionally not implemented. The operator should provide known test objects/accounts within an authorized lab or test tenant.

**Interpretation:** potential BOLA; compare ownership, role and tenant semantics manually before confirming.

## Input validation

Mutations are deliberately small:

- empty value;
- wrong primitive type;
- 64-character boundary string;
- omission of required JSON fields when write methods are explicitly enabled.

A 5xx response is treated as a low-severity validation robustness signal. Verbose trace content raises the misconfiguration signal.

## Sensitive data exposure

The analyzer recursively checks successful JSON responses for secret-like field names such as `password`, `secret`, `access_token`, and `api_key`.

This is a heuristic. A field name alone does not prove that its value is sensitive, and a secure system may legitimately return a token at an authentication endpoint. Human triage is required.

## Rate/resource controls

The project does **not** flood endpoints. It only records whether common rate-limit headers are visible on one sampled GET response and recommends server-side verification.

## Not implemented by design

- credential stuffing or password attacks;
- SQL injection exploit payload libraries;
- SSRF exploit chains;
- unrestricted path/ID enumeration;
- denial-of-service or high-volume fuzzing;
- destructive data mutation;
- malware, shell execution, persistence, or lateral movement.

# Architecture and safety boundaries

AuthMatrix is a policy-driven authorization checker with four stages:

1. **Configuration validation** loads a local YAML policy and requires an explicit
   authorization declaration plus an exact allowlist entry for the target.
2. **Operation inventory** parses a local OpenAPI 3.x JSON/YAML file. Importing
   a specification is static; it never contacts its servers or follows references.
3. **Authorization checks** send only the configured identity/operation/resource
   matrix. The HTTP client has a timeout, response-size limit, request-count
   limit, disabled environment proxies, and redirects disabled.
4. **Reporting** records status metadata and policy decisions. Response bodies,
   authentication headers, tokens, passwords, and environment values are never
   copied into results.

The current implementation intentionally permits targets only at literal loopback
IP addresses (`127.0.0.1` or `::1`) listed in `scope.allowed_hosts`. It does not
resolve hostnames or accept a network target. The built-in demo API is read-only.
Destructive HTTP methods are rejected unless explicitly enabled in a local policy;
they are not used by the included examples or lab.

The BOLA and BFLA labels identify policy checks, not proof of a complete
vulnerability assessment. A successful response to an expected-deny request is
reported as a finding. AuthMatrix does not infer a correct authorization policy
from an API specification.

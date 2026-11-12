# Architecture and safety boundaries

AuthMatrix is a policy-driven authorization checker with six existing
scanner/application stages plus the asset inventory foundation:

1. **Configuration validation** loads a local YAML policy and requires an explicit
   authorization declaration plus an exact allowlist entry for the target.
2. **Operation mapping** optionally matches policy operation IDs to operations in
   a local OpenAPI 3.x JSON/YAML document. A separate local YAML mapping provides
   every request parameter and JSON body value explicitly. OpenAPI defaults,
   examples, enums, server URLs, and schemas are never used to invent request
   values. Remote references are never fetched; referenced path items, operations,
   parameters, and request bodies are rejected.
3. **Authorization checks** send only the configured identity/operation/resource
   matrix. The scanner serializes supported path, query, and header parameters
   using their OpenAPI styles, sends explicitly mapped JSON bodies, and skips
   incomplete or unsupported operations with reasons. The HTTP client has a
   timeout, response-size limit, request-count limit, disabled environment
   proxies, and redirects disabled.
4. **Reporting** records status metadata and policy decisions. Response bodies,
   request parameter values, authentication headers, tokens, passwords, and
   environment values are never copied into results. BOLA deny checks require
   owner metadata and matching returned IDs; BFLA deny findings require a
   configured `response_evidence_path` that resolves to non-empty scalar data.
   A successful HTTP status alone is not sufficient evidence for either class.
5. **Dashboard** serves packaged local static assets and calls the same
   policy/scanner services as the CLI. It can select local OpenAPI documents and
   explicit values mappings for scans and displays skipped operations and
   inconclusive results.
6. **Web persistence** stores scan status, metadata, and sanitized result
   documents in a local SQLite database. It is bounded to 1,000 scans; scans
   left running at process restart are marked failed.
7. **Asset inventory and scope preview** store canonical host/address/network
   declarations, current authorization metadata, and explicit include/exclude
   entries in that same protected SQLite database. A shared backend evaluator
   enforces date, active-state, inclusion, and exclusion rules for preview and
   proposed-target validation. It performs no network or DNS requests.

The current implementation intentionally permits targets only at literal loopback
IP addresses (`127.0.0.1` or `::1`) listed in `scope.allowed_hosts`. It does not
resolve hostnames or accept a network target. The built-in demo API is read-only.
Destructive HTTP methods are rejected unless explicitly enabled in a local policy;
they are not used by the included examples or lab.

Asset inventory authorization is separate from scanner policy authorization.
Inventory creation does not authorize or launch a scan, and the inventory scope
evaluator is not currently connected to CLI or API scanner execution. Existing
scans continue to use their existing loopback-only policy allowlist. Future
scanners must reuse the central scope evaluator and perform execution-time DNS/IP
validation, destination pinning, and redirect checks. DNS rebinding defenses and
hostname-to-IP authorization are not implemented by asset registration or scope
preview.

The BOLA and BFLA labels identify policy checks, not proof of a complete
vulnerability assessment. AuthMatrix does not infer a correct authorization
policy from an API specification. BFLA evidence is a boolean presence check at
the configured JSON response path; the response value itself is not retained.
OpenAPI schema constraints beyond parameter JSON types are not validated.

The web API accepts only server-side policy filenames; scan target URLs and
credentials are never accepted from browser input. Every scan requires an
explicit authorization acknowledgement. Policy and OpenAPI files are resolved
inside their configured local directories, and cross-origin state-changing API
requests are rejected unless their Origin is explicitly trusted. A scan lock
prevents concurrent scans in one server process. The `authmatrix web` command
binds only to a literal loopback IP and uses one worker. Do not expose the
dashboard to public networks.

OpenAPI value mappings use the policy operation ID as their key, with an
optional `operation_id` when the OpenAPI operation ID differs. Parameter values
are keyed by their OpenAPI parameter name; `body` contains an explicit JSON
value, and `content_type` may select a declared JSON media type. The exact
`$authmatrix_resource_id: true` value binds one BOLA path parameter to the
policy's configured resource IDs. `$authmatrix_by_identity` provides an
explicit value for every configured identity. Missing required inputs, missing
operation IDs, unsupported content types, and disabled destructive operations
are reported as skipped; no sample or default is substituted. Cookie parameters,
non-JSON request bodies, `allowReserved`, and `allowEmptyValue` parameters are not
sent. `Authorization`, `Cookie`, `Host`, and `Content-Type` header parameters
cannot override scanner or transport settings. Mapping files are bounded to 1
MiB and should be protected like credentials, even though their contents are
not saved in scan results.

The SQLite database is stored under `~/.authmatrix` by default (or the
directory configured by `AUTHMATRIX_DATA_DIR`). It uses restrictive file
permissions: its directory is restricted to the current user, the database is
restricted to mode `0600`, and symlink/hardlink database paths are rejected.
The directory must be owned by the account running AuthMatrix. Existing scan
data is retained when permissions are tightened; unrelated directory entries
are not removed. Scan results and inventory data are not encrypted at rest.
Inventory entries store the current authorization record only, not historical
authorization revisions. Authorization references should be identifiers, not
secrets or uploaded legal documents.

The dashboard follows a local, single-user trust model and does not authenticate
readers. Any local process able to reach it can inspect scan history and
sanitized reports. Do not expose it to untrusted users or networks; adding
authentication requires a separate design.

The Docker Compose dashboard has no default demo credentials. Its optional
local lab profile uses public demo-only credentials, which must never be reused
for real systems. Compose publishes the service only on host loopback, runs the
process as an unprivileged user, drops Linux capabilities, and uses a read-only
container filesystem with a persistent data volume. The image listens on all
interfaces only inside its network namespace so port forwarding works; the
Compose host binding remains loopback-only. The optional lab service is
profile-gated, not published to the host, health-checked, and uses the same
container restrictions. Docker runtime behavior is not verified in the current
development environment because Docker CLI and Compose are unavailable.

# AuthMatrix

**Policy-driven API authorization testing for explicitly authorized local targets.**

AuthMatrix is a Python-based API security testing tool designed to identify authorization weaknesses such as **BOLA/IDOR** and **BFLA** through policy-driven testing. It evaluates access-control decisions across configured identities, resources, and operations, then generates sanitized JSON or HTML reports.

> [!WARNING]
> **Scope boundary:** AuthMatrix currently accepts only literal loopback IPs (`127.0.0.1` or `::1`). It does not scan public hosts, resolve hostnames, follow redirects, or store response bodies. Use it only on systems you own or are explicitly authorized to test.

---

## Features

- Policy-driven API authorization testing.
- BOLA/IDOR and BFLA authorization checks.
- Multi-identity and resource ownership validation.
- OpenAPI 3.x inventory and explicit operation-driven scanning.
- Configurable request, response-size, and timeout limits.
- Environment-based authentication credentials.
- JSON and HTML security reports.
- Scan baseline comparison.
- Local vulnerable and fixed API lab environments.
- Persistent scan history and a local-first FastAPI dashboard.
- Local OpenAPI operation inventory browsing.
- Sanitized findings and evidence handling.

## Requirements

- Python 3.11 or newer.
- Git.
- A virtual environment (recommended).

The project has also been installed and exercised with Python 3.14.2.

## Installation

Clone the repository:

```bash
git clone https://github.com/RudraGoti/authmatrix.git
cd authmatrix
```

Create and activate a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
```

Install AuthMatrix and development dependencies:

```bash
python -m pip install -e ".[dev]"
```

Verify the installation:

```bash
authmatrix version
authmatrix config-check --config examples/policy.yaml
```

## Configure authentication

Add the local demo credentials to your process environment:

```bash
export AUTHMATRIX_ALICE_TOKEN=alice-local-token
export AUTHMATRIX_BOB_TOKEN=bob-local-token
export AUTHMATRIX_ADMIN_TOKEN=admin-local-token
```

Validate the authentication environment:

```bash
authmatrix config-check \
  --config examples/policy.yaml \
  --check-auth-env
```

> [!NOTE]
> These sample credentials are public, hard-coded lab values for local demos
> only. **Never use them for real systems, production deployments, or as a
> substitute for real secret management.** Use credentials specifically issued
> for an explicitly authorized test environment.

---

## Quick Start: Safe Local Lab

AuthMatrix includes a deliberately vulnerable and a fixed read-only API lab.

**Terminal 1 — Start the vulnerable lab:**

```bash
authmatrix lab --mode vulnerable --host 127.0.0.1 --port 8000
```

**Terminal 2 — Run authorization tests:**

```bash
authmatrix test \
  --config examples/policy.yaml \
  --output scan-results.json
```

Scan result files are created without overwriting existing files. Use `--force`
only when you intend to replace the selected output.

Generate an HTML report:

```bash
authmatrix report scan-results.json \
  --format html \
  --output reports/vulnerable.html
```

Report outputs are created without overwriting existing files. To deliberately
replace a report, pass `--force` after reviewing the destination path.

The vulnerable demo should report object-access and administrator-function access for unauthorized identities.

Stop the vulnerable lab with `Ctrl+C`, then start the fixed version:

```bash
authmatrix lab --mode fixed --host 127.0.0.1 --port 8000
```

Run the same policy again. The fixed implementation should pass without authorization findings.

The example policy contains 9 expected requests: three identities against two owned items and one administrator-only operation.

If you change the local lab port, update `scope.base_url` in a copied policy file.

---

## Local API

AuthMatrix includes a FastAPI backend that exposes local health, status, and authorization-scanning endpoints.

### Start the API

From the repository root:

```bash
source .venv/bin/activate
authmatrix web
```

The server listens at:

```text
http://127.0.0.1:8001
```

> [!IMPORTANT]
> `authmatrix web` accepts only a literal loopback IP address. Do not expose the
> dashboard to public networks. The API also requires an explicit authorization
> acknowledgement for every scan submission.

The dashboard is a local, single-user interface and has no login or
cookie-backed session system. Treat the local operating-system account as
trusted; do not share the service with untrusted users. State-changing API
requests validate browser Origin/fetch metadata, and scan start/completion/failure
events are logged using scan IDs and policy filenames without logging secrets.

Open `http://127.0.0.1:8001/` for the dashboard. It shows live API health,
persisted scan totals, validated policy metadata, findings, recent activity,
JSON/HTML reports, and comparisons between completed scans.

Scan metadata and sanitized results are stored in SQLite at
`~/.authmatrix/authmatrix-scans.sqlite3` by default. Set
`AUTHMATRIX_DATA_DIR` to change the containing directory. The store retains at
most 1,000 scans and marks scans interrupted by a server restart as failed.
Credentials and response bodies are not stored. Protect the data directory as
local scan data; it is not encrypted at rest. The directory must be owned by
the account running AuthMatrix and is restricted to that account; the database
file is mode `0600`. Existing scan data is preserved while restrictive
permissions are applied. Do not point `AUTHMATRIX_DATA_DIR` at a shared or
general-purpose directory.

### API Documentation

Once the server is running:

| Resource | URL |
|---|---|
| Interactive API documentation | http://127.0.0.1:8001/docs |
| OpenAPI schema | http://127.0.0.1:8001/api/openapi.json |

### Available Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Returns API health and version information. |
| `GET` | `/api/status` | Returns readiness and supported capabilities. |
| `GET` | `/api/policies` | Lists valid YAML policies under the configured policy directory. |
| `GET` | `/api/policies/{name}` | Returns safe policy metadata without credentials. |
| `GET` | `/api/openapi/specs` | Lists parseable local OpenAPI documents. |
| `GET` | `/api/openapi/specs/{name}` | Returns a sanitized local operation inventory. |
| `GET` | `/api/openapi/mappings` | Lists explicit local `*.mapping.yaml` value files. |
| `POST` | `/api/scans` | Runs a policy scan, optionally mapped to OpenAPI, after authorization acknowledgement. |
| `GET` | `/api/scans` | Returns bounded, persistent scan history and totals. |
| `GET` | `/api/scans/{id}` | Returns scan status or a completed scan result. |
| `GET` | `/api/findings` | Lists findings from completed scans retained in SQLite. |
| `POST` | `/api/comparisons` | Compares two completed scans for the same target. |
| `GET` | `/api/scans/{id}/report.json` | Returns a completed scan's sanitized JSON report. |
| `GET` | `/api/scans/{id}/report.html` | Returns an escaped HTML report. |

The dashboard's Policies, Findings, Reports, and History views use these API
responses directly. New Scan displays the selected policy's target, authorized
hosts, identities and roles, operations, and request/time/response limits before
execution. Policies are validated both when selected and again by the existing
scan engine; the browser cannot submit a target URL or replace policy safety
limits.

A scan runs synchronously in the API request, while the bounded scanner itself
runs in a worker thread. Its persistent history record is `running` only while
execution is active, then `completed` or `failed`; there is no queued state or
percentage progress. A second simultaneous scan is rejected. The UI polls
bounded scan history for truthful running status and displays the final result
or sanitized error. Cancellation is not supported because the scanner has no
safe cancellation mechanism. Report identifiers are generated by AuthMatrix;
the API does not accept report file paths.

### Example Scan Request

The scan endpoint accepts a relative `policy_path` pointing to a YAML policy file inside the configured policy directory.

```json
{
  "policy_path": "policy.yaml",
  "authorization_confirmed": true
}
```

By default, policy files are loaded from the repository's `examples/` directory.
The dashboard requires the authorization checkbox; API clients must explicitly
send `authorization_confirmed: true`.

To use a different server-side policy directory, set:

```bash
export AUTHMATRIX_POLICY_DIR=/path/to/policies
```

The API does not accept arbitrary target URLs or credentials in scan requests. Existing AuthMatrix policy and scope restrictions remain enforced.

OpenAPI browsing is limited to parseable JSON/YAML files directly under the
local `examples/` directory by default. Set `AUTHMATRIX_OPENAPI_DIR` to select
another server-side directory. OpenAPI value mappings are limited to
`*.mapping.yaml` files in that directory by default; set
`AUTHMATRIX_OPENAPI_VALUES_DIR` to select a separate mapping directory. The
dashboard does not fetch remote `$ref` documents or use schema examples to
generate request values. OpenAPI scans still use the selected policy's target,
authorization declaration, identities, resource ownership, expected decisions,
and request limits. Values mapping files are bounded to 1 MiB.

### GitHub Codespaces

Install the project in the Codespace terminal:

```bash
python -m pip install -e ".[dev]"
```

Set `AUTHMATRIX_TRUSTED_ORIGINS` to the exact forwarded Codespaces origin for
port 8001, then start the server on loopback:

```bash
export AUTHMATRIX_TRUSTED_ORIGINS="https://<codespace-name>-8001.app.github.dev"
authmatrix web
```

Keep the forwarded port private. The trusted origin setting is required for
browser-submitted scans when using a non-default Codespaces origin; it does not
change the scanner's loopback-only target scope.

### Docker Compose

Docker Compose provides a local-only deployment with a persistent data volume:

```bash
docker compose up --build
```

The published host port is bound to `127.0.0.1:8001`. The image's default
server command listens on all interfaces inside the container; this is required
for container port forwarding. Compose publishes it only on host loopback. Do
not change the host-side bind to `0.0.0.0`. The container runs as an
unprivileged user (UID `10001`), drops Linux capabilities, and uses a read-only
root filesystem. The persistent named volume is initialized from the image's
`/data` directory, which is owned by UID `10001`; a pre-existing volume created
with different ownership must be corrected before startup. The optional lab
service uses the same read-only filesystem, dropped capabilities, and
`no-new-privileges` restriction; it is health-checked and stopped with `SIGINT`
for graceful server cleanup.

Docker runtime verification has **not** been performed in the current
environment (`docker --version` and `docker compose version` both report that
the command is unavailable). Static configuration tests cover the image
command, permissions, volume, loopback publishing, health checks, container
restrictions, credentials, and optional lab profile; they do not prove that the
images build or containers run. Use the following sequence on a Docker-capable
machine to verify build, health, dashboard access, explicit authorization,
vulnerable/fixed results, reports, and persistent history:

The dashboard service does not provide demo credential defaults. Set
`AUTHMATRIX_ALICE_TOKEN`, `AUTHMATRIX_BOB_TOKEN`, and
`AUTHMATRIX_ADMIN_TOKEN` to credentials for the explicitly authorized local
test target before running scans. Do not put real credentials in the Compose
file, shell history, or source control.

For the bundled local demo only, set its public sample credentials in the
terminal and run the optional lab profile:

```bash
export AUTHMATRIX_ALICE_TOKEN=alice-local-token
export AUTHMATRIX_BOB_TOKEN=bob-local-token
export AUTHMATRIX_ADMIN_TOKEN=admin-local-token
docker --version
docker compose version
docker compose config --quiet
docker compose --profile lab up --build --wait --detach
docker compose --profile lab ps
curl -fsS http://127.0.0.1:8001/api/health
curl -fsS http://127.0.0.1:8001/ -o /dev/null

# A scan without an explicit authorization acknowledgement must be rejected.
test "$(curl -sS -o /tmp/authmatrix-no-consent.json -w '%{http_code}' \
  -H 'Content-Type: application/json' \
  -d '{"policy_path":"policy.yaml"}' \
  http://127.0.0.1:8001/api/scans)" = "403"

# Vulnerable lab: the saved report should contain findings.
export VULNERABLE_SCAN_ID="$(curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"policy_path":"policy.yaml","authorization_confirmed":true}' \
  http://127.0.0.1:8001/api/scans \
  | python -c 'import json,sys; r=json.load(sys.stdin); assert r["summary"]["findings"] > 0; print(r["scan_id"])')"
curl -fsS \
  "http://127.0.0.1:8001/api/scans/${VULNERABLE_SCAN_ID}/report.json" \
  -o /tmp/authmatrix-vulnerable-report.json

# Restart just the lab in fixed mode; its health status should become healthy.
AUTHMATRIX_LAB_MODE=fixed docker compose --profile lab up \
  --wait --detach --force-recreate lab
docker compose --profile lab ps
export FIXED_SCAN_ID="$(curl -fsS \
  -H 'Content-Type: application/json' \
  -d '{"policy_path":"policy.yaml","authorization_confirmed":true}' \
  http://127.0.0.1:8001/api/scans \
  | python -c 'import json,sys; r=json.load(sys.stdin); assert r["summary"]["findings"] == 0; print(r["scan_id"])')"
curl -fsS \
  "http://127.0.0.1:8001/api/scans/${FIXED_SCAN_ID}/report.html" \
  -o /tmp/authmatrix-fixed-report.html

# Recreate the stack without deleting the named volume, then verify both scans remain.
docker compose down
AUTHMATRIX_LAB_MODE=fixed docker compose --profile lab up --wait --detach
curl -fsS http://127.0.0.1:8001/api/scans \
  | python -c 'import json,os,sys; ids={s["scan_id"] for s in json.load(sys.stdin)["scans"]}; assert {os.environ["VULNERABLE_SCAN_ID"],os.environ["FIXED_SCAN_ID"]} <= ids'
docker compose down
```

The demo API is not published to the host. It binds to loopback inside the
container, where the dashboard scanner can reach it. The lab profile defaults
to the deliberately vulnerable, read-only demo; choose the fixed variant with
`AUTHMATRIX_LAB_MODE=fixed docker compose --profile lab up`. Default credentials
above are public lab-only values. **Never reuse them in real environments.**
The environment exports make them available to the scanner and demo API; unset
or replace them after the local demo. `docker compose down` preserves scan
history in the named volume; do not use `docker compose down -v` if you want to
retain it.

Local OpenAPI documents are limited to 2 MiB by default. Configure a different
limit using `AUTHMATRIX_OPENAPI_MAX_BYTES` (1 byte through 16 MiB); oversized
documents are rejected before parsing and the read itself remains bounded.
This setting applies to dashboard inventory and scan requests. The CLI uses
the 2 MiB default.

---

## OpenAPI Inventory and Scanning

AuthMatrix can inspect a local OpenAPI 3.x JSON or YAML description without
making network requests. The CLI writes an inventory:

```bash
authmatrix import-openapi \
  examples/openapi.yaml \
  --output openapi-inventory.json
```

The importer extracts supported HTTP operations and their path, query, and
header parameters, including parameter schemas and `style`/`explode`
serialization metadata. `authmatrix test` can also execute a policy matrix
using operations from a local OpenAPI specification and explicitly supplied
values:

```bash
authmatrix test \
  --config examples/policy.yaml \
  --openapi examples/openapi.yaml \
  --values examples/openapi.mapping.yaml \
  --output openapi-scan.json
```

The mapping file keys each entry by the policy operation ID. `operation_id` is
optional when the OpenAPI ID differs. Required path, query, and header
parameters need explicit values; optional parameters without mappings are
omitted. A required JSON request body needs an explicit `body` value. No
parameter values, bodies, targets, or authorization decisions are inferred
from OpenAPI examples, defaults, enums, schemas, or server declarations.

The example BOLA mapping binds the policy's configured resource IDs to a path
parameter:

```yaml
operations:
  read_item:
    operation_id: readItem
    parameters:
      item_id:
        $authmatrix_resource_id: true
  read_admin_reports:
    operation_id: readAdminReports
```

Use `$authmatrix_by_identity` when an explicitly chosen value differs by
identity; it must contain an entry for every policy identity. JSON request
bodies use `body`; `content_type` can select one of the operation's declared
JSON media types. These local mapping files may contain sensitive test data and
should be protected like credentials.

The scanner supports OpenAPI path styles `simple`, `label`, and `matrix`;
query styles `form`, `spaceDelimited`, `pipeDelimited`, and `deepObject`; and
header style `simple`. Arrays and objects use the declared `explode` behavior.
Parameter values are type-checked against the schema's JSON type, but schema
constraints such as patterns, ranges, and enums are not validated. Cookie
parameters, non-JSON request bodies, `allowReserved`, and `allowEmptyValue`
parameters are not sent. Remote references are never fetched; referenced path
items, operations, parameters, and request bodies are rejected.
`Authorization`, `Cookie`, `Host`, and `Content-Type` header parameters are not
overridable; configured credentials come from the policy environment settings,
and JSON body media types are selected with `content_type`.

Unmapped operations, absent required values, unsupported body formats, and
destructive methods disabled by policy are reported as skipped. They do not
cause fabricated requests. A BOLA deny finding requires owner metadata and a
matching returned resource ID. A BFLA deny finding requires a configured
`response_evidence_path` in the policy that resolves to non-empty scalar JSON
data; a successful HTTP status alone is not a finding. For example, the
read-only lab policy uses `response_evidence_path: reports[*]`.

The dashboard offers the same optional OpenAPI document and mapping-file
selections. Results, skipped-operation reasons, and inconclusive checks are
included in saved JSON/HTML reports and scan history. The operation inventory
remains available separately through `authmatrix import-openapi`.

---

## BOLA Response ID Verification

The `response_id_path` setting identifies the JSON field containing a returned resource ID.

It defaults to `id` and supports:

| Format | Example |
|---|---|
| Direct field | `id` |
| Nested field | `data.order.id` |
| Array index | `data.orders[0].id` |
| Wildcard selection | `data.orders[*].id` |

Wildcard paths extract multiple IDs. Duplicate IDs are removed while preserving order.

String and integer IDs are accepted; invalid individual values are skipped.

Extraction is bounded to:
- 100 candidate values at each traversal step.
- A maximum of 100 unique IDs.

Missing paths, unusable values, or exceeding either limit produce an inconclusive check rather than an automatic finding.

A BOLA finding requires verification that the requested resource ID appears among the returned IDs when policy expected denial.

Extracted IDs are used only for verification and evidence. AuthMatrix does not automatically send requests for discovered IDs.

Existing request, response-size, scope, and redaction limits remain in force.

---

## Policy and Architecture

The example policy at `examples/policy.yaml` explicitly declares:

- An authorized loopback target and exact allowed-host list.
- Request, response-size, and timeout limits.
- Identities with roles and environment-variable-backed bearer credentials.
- Resource IDs and ownership metadata.
- Expected allow/deny decisions for every identity/resource pair and operation.

### HTTP Method Restrictions

`GET`, `HEAD`, and `OPTIONS` are the only methods permitted by default.

The included demo server is read-only. The policy parser rejects destructive methods unless:

```yaml
scope:
  allow_destructive: true
```

is deliberately configured.

Keep destructive methods disabled unless testing a disposable, explicitly authorized local service.

For more details, see [Architecture and Safety Boundaries](docs/architecture.md).

---

## Scan Baseline Comparison

Compare a new scan with a previously saved scan report:

```bash
authmatrix compare \
  --baseline baseline.json \
  --current current.json \
  --output comparison.json
```

Findings are classified into three categories:

| Classification | Description |
|---|---|
| **New** | Present only in the current scan. |
| **Fixed** | Present only in the baseline. |
| **Recurring** | Present in both scans. |

Matching uses stable fingerprints based on category, operation, HTTP method, path, identity, and resource ID.

Changes to title or severity alone do not create a new finding.

Both reports must be valid AuthMatrix scan reports for the same target. Missing, malformed, or incompatible reports are rejected.

---

## Reports and Sensitive Data

AuthMatrix reports include:

- Policy checks.
- HTTP status codes.
- Finding severity.
- Identity labels.
- Reproduction method and path.
- Remediation guidance.

Reports never include request headers, tokens, passwords, or response bodies.

> [!CAUTION]
> Treat generated reports as potentially sensitive. Routes and identity labels can reveal application structure. Protect reports and avoid committing sensitive scan results to GitHub.

Generated reports and common scan-result files are ignored by Git.

---

## Testing and Linting

Run the complete test suite:

```bash
python -m pytest
```

Run Ruff linting:

```bash
ruff check .
```

Build a wheel and verify the frontend assets are included:

```bash
python -m pip wheel . --no-deps --wheel-dir dist
```

The dashboard OpenAPI page provides static inventory. Starting an OpenAPI scan
requires explicit local values mappings and an authorized policy; importing
does not generate parameter values or infer authorization decisions.

---

## Limitations

- This MVP is intentionally loopback-only; it is not a general-purpose remote scanner.
- It does not verify ownership semantics beyond the supplied policy.
- It currently supports bearer and HTTP Basic credentials from environment variables, not OAuth flows, cookies, client certificates, or secret managers.
- It tests explicitly declared operations and IDs only.
- OpenAPI scanning requires complete explicit values; unmapped operations are skipped.
- OpenAPI schema validation currently checks parameter JSON types, not all schema constraints.
- The lab demonstrates read-only GET authorization only; it does not exercise state changes, concurrency, pagination, GraphQL, or multi-step workflows.
- Findings require configured ownership or response-data evidence; passing tests do not establish that an API is secure.

## Responsible Use

Obtain authorization before testing.

Define only identities, operations, and resources in scope. Use disposable local data, review the policy before each run, and protect generated reports.

Do not remove the loopback scope restriction to test a third-party system.

---

## Screenshots

<!-- Add terminal and HTML report screenshots here when available. -->

---

**Built for learning, testing, and improving API authorization security.**

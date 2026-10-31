# AuthMatrix

Policy-driven API authorization checks for **explicitly authorized local
targets**. The MVP tests configured BOLA/IDOR and BFLA authorization decisions,
and produces sanitized JSON or HTML reports.

> **Scope boundary:** AuthMatrix currently accepts only literal loopback IPs
> (`127.0.0.1` or `::1`). It does not scan public hosts, resolve hostnames,
> follow redirects, or store response bodies. Use it only on systems you own or
> are authorized to test.

## Requirements and installation

- Python 3.11 or newer (the project has also been installed and exercised with
  Python 3.14.2).
- The included demo lab binds only to loopback.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
```

Verify installation and policy:

```bash
authmatrix version
authmatrix config-check --config examples/policy.yaml
```

Add credentials to the process environment; the sample tokens are only for the
local demo:

```bash
export AUTHMATRIX_ALICE_TOKEN=alice-local-token
export AUTHMATRIX_BOB_TOKEN=bob-local-token
export AUTHMATRIX_ADMIN_TOKEN=admin-local-token
authmatrix config-check --config examples/policy.yaml --check-auth-env
```

## Quick start: safe local lab

In terminal 1, start the deliberately vulnerable, read-only API:

```bash
authmatrix lab --mode vulnerable --host 127.0.0.1 --port 8000
```

In terminal 2, run the policy matrix and render a report:

```bash
authmatrix test --config examples/policy.yaml --output scan-results.json
authmatrix report scan-results.json --format html --output reports/vulnerable.html
```

The vulnerable demo should report object access and administrator-function
access for non-authorized identities. Stop it with Ctrl+C, then start the fixed
version using the same command with `--mode fixed`. The same test policy should
then pass with no findings.

The policy includes 9 expected requests (three identities against two owned
items and one administrator-only operation). If a local port is changed, update
`scope.base_url` in a copied policy file. To inspect an API description without
making network requests:

```bash
authmatrix import-openapi examples/openapi.yaml --output openapi-inventory.json
```

Run the test suite and lint:

```bash
python -m pytest
ruff check .
```

## Policy and architecture

`examples/policy.yaml` explicitly declares:

- an authorized loopback target and an exact allowed-host list;
- request, response-size, and timeout limits;
- identities with roles and environment-variable-backed bearer credentials;
- resource IDs and ownership metadata;
- expected allow/deny decisions for every identity/resource pair and operation.

### BOLA response ID verification

`response_id_path` identifies the JSON field containing a returned resource ID. It defaults to `id` and supports nested fields, numeric array indexes, and wildcard selection.

Examples: `id`, `data.order.id`, `data.orders[0].id`, and `data.orders[*].id`.

Wildcard paths extract multiple IDs. Duplicate IDs are removed while preserving order. String and integer IDs are accepted; invalid individual values are skipped. Extraction is bounded to 100 candidate values at each traversal step and a maximum of 100 unique IDs. Missing paths, unusable values, or exceeding either limit produce an inconclusive check rather than an automatic finding.

A BOLA finding requires verification that the requested resource ID appears among the returned IDs when policy expected denial. Extracted IDs are used only for verification and evidence; AuthMatrix does not automatically send requests for discovered IDs. Existing request, response-size, scope, and redaction limits remain in force.

`GET`, `HEAD`, and `OPTIONS` are the only methods permitted by default. The
included demo server is read-only. The policy parser rejects destructive methods
unless `scope.allow_destructive: true` is deliberately set; keep it disabled
unless testing a disposable, explicitly authorized local service.

The OpenAPI importer parses local OpenAPI 3.x JSON/YAML and extracts supported
HTTP operations with their path, query, and header parameters. It merges
path-level parameters with operation-level parameters, allowing operation-level
definitions to override matching path-level definitions. Required path parameters
must match the route placeholders. Invalid definitions, unsupported parameter
locations, styles, content-based parameters, and unresolved parameter references
are rejected.

The importer does not fetch remote references, select a scan target, generate
parameter values, or infer access-control rules. Imported parameters are inventory
metadata only; they do not automatically become scan inputs. The policy remains
the source of expected access decisions. See
[architecture and safety boundaries](docs/architecture.md).

## Scan baseline comparison

Compare a new scan with a previously saved scan report:

```bash
authmatrix compare --baseline baseline.json --current current.json --output comparison.json
```

Findings are classified as:
- **New:** present only in the current scan.
- **Fixed:** present only in the baseline.
- **Recurring:** present in both scans.

Matching uses stable fingerprints based on category, operation, HTTP method, path, identity, and resource ID. Changes to title or severity alone do not create a new finding.

Both reports must be valid AuthMatrix scan reports for the same target. Missing, malformed, or incompatible reports are rejected. The comparison output is JSON with summary counts and finding details.

## Reports and sensitive data

Reports include policy checks, status codes, finding severity, identity labels,
reproduction method/path, and remediation guidance. They never include request
headers, tokens, passwords, or response bodies. Treat reports as potentially
sensitive anyway: routes and identity labels can reveal application structure.
Generated reports and common scan-result files are ignored by Git.

## Limitations

- This MVP is intentionally loopback-only; it is not a general-purpose remote
  scanner and does not verify ownership semantics beyond the supplied policy.
- It currently supports bearer and HTTP Basic credentials from environment
  variables, not OAuth flows, cookies, client certificates, or secret managers.
- It tests explicitly declared operations and IDs only. OpenAPI import is an
  inventory, not automatic test generation.
- The lab demonstrates read-only GET authorization only; it does not exercise
  state changes, concurrency, pagination, GraphQL, or multi-step workflows.
- A finding is an observed successful response where policy expected denial;
  passing tests do not establish that an API is secure.

## Responsible use

Obtain authorization before testing. Define only identities, operations, and
resources in scope; use disposable local data; review the policy before each
run; and protect generated reports. Do not remove the loopback scope restriction
to test a third-party system.

## Screenshots

<!-- Add terminal and HTML report screenshots here when available. -->
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
- OpenAPI 3.x inventory importer.
- Configurable request, response-size, and timeout limits.
- Environment-based authentication credentials.
- JSON and HTML security reports.
- Scan baseline comparison.
- Local vulnerable and fixed API lab environments.
- FastAPI backend for local API access.
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
> These sample credentials are intended only for the local demonstration environment.

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

Generate an HTML report:

```bash
authmatrix report scan-results.json \
  --format html \
  --output reports/vulnerable.html
```

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
uvicorn authmatrix.web.app:app --host 127.0.0.1 --port 8001
```

The API listens at:

```text
http://127.0.0.1:8001
```

> [!IMPORTANT]
> The development server binds to loopback only. Do not expose it to public networks.

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
| `POST` | `/api/scans` | Runs an authorization scan using a YAML policy file. |

### Example Scan Request

The scan endpoint accepts a relative `policy_path` pointing to a YAML policy file inside the configured policy directory.

```json
{
  "policy_path": "policy.yaml"
}
```

By default, policy files are loaded from the repository's `examples/` directory.

To use a different server-side policy directory, set:

```bash
export AUTHMATRIX_POLICY_DIR=/path/to/policies
```

The API does not accept arbitrary target URLs or credentials in scan requests. Existing AuthMatrix policy and scope restrictions remain enforced.

---

## OpenAPI Import

AuthMatrix can inspect a local OpenAPI 3.x JSON or YAML description without making network requests.

```bash
authmatrix import-openapi \
  examples/openapi.yaml \
  --output openapi-inventory.json
```

The importer extracts supported HTTP operations and their path, query, and header parameters.

It does not:

- Fetch remote references.
- Select a scan target.
- Generate parameter values.
- Infer authorization rules.
- Automatically turn imported parameters into scan inputs.

Imported parameters are inventory metadata only. The policy remains the source of expected access-control decisions.

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

---

## Limitations

- This MVP is intentionally loopback-only; it is not a general-purpose remote scanner.
- It does not verify ownership semantics beyond the supplied policy.
- It currently supports bearer and HTTP Basic credentials from environment variables, not OAuth flows, cookies, client certificates, or secret managers.
- It tests explicitly declared operations and IDs only.
- OpenAPI import is an inventory feature, not automatic test generation.
- The lab demonstrates read-only GET authorization only; it does not exercise state changes, concurrency, pagination, GraphQL, or multi-step workflows.
- A finding is an observed successful response where policy expected denial. Passing tests do not establish that an API is secure.

## Responsible Use

Obtain authorization before testing.

Define only identities, operations, and resources in scope. Use disposable local data, review the policy before each run, and protect generated reports.

Do not remove the loopback scope restriction to test a third-party system.

---

## Screenshots

<!-- Add terminal and HTML report screenshots here when available. -->

---

**Built for learning, testing, and improving API authorization security.**

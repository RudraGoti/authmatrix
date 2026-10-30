# Local demo APIs

The vulnerable and fixed variants share one read-only implementation in
`src/authmatrix/lab.py`; choose the variant when launching it:

```bash
authmatrix lab --mode vulnerable --host 127.0.0.1 --port 8000
authmatrix lab --mode fixed --host 127.0.0.1 --port 8000
```

The lab binds only to a literal loopback IP. Its sample bearer tokens are
`alice-local-token`, `bob-local-token`, and `admin-local-token`. Endpoints are
`GET /items/{id}` and `GET /admin/reports`; all write methods are rejected.
The vulnerable mode omits object- and function-level authorization. The fixed
mode permits item access only to its owner or an administrator and restricts
reports to administrators.

These credentials and records are for local demonstrations only. Do not reuse
them in another environment.

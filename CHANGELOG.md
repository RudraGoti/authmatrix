# Changelog

All notable changes to AuthMatrix will be documented in this file.

This project follows a release-oriented changelog format. Entries under
Unreleased describe changes merged into the development branch that have not
yet been included in a published release.

## [Unreleased]

### Added
- Policy-driven API authorization testing for BOLA/IDOR and BFLA.
- Multi-identity testing and configurable resource ownership checks.
- OpenAPI operation inventory and explicitly mapped API scanning.
- JSON and HTML reports with sanitized findings and evidence.
- Scan history, baseline comparison, and a local-first FastAPI dashboard.
- Asset inventory with explicit authorization metadata and scope exclusions.
- Inventory-scoped execution with bounded DNS validation and pinned
  connections.
- Metadata-only web security posture assessment for authorized inventory
  assets.
- Docker image build validation and Docker Compose runtime smoke tests in
  GitHub Actions.

### Security
- Hardened policy loading, authorization scope evaluation, and inventory
  execution controls.
- Added explicit authorization confirmation and bounded execution policies.
- Restricted the default dashboard deployment to host loopback in Docker
  Compose.
- Added container hardening and runtime validation in CI.

### Documentation
- Documented installation, configuration, responsible use, architecture,
  deployment, and security limitations.

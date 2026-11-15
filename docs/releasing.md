# Release procedure

## Prepare

- Start from an up-to-date main branch with a clean worktree.
- Review changes and update CHANGELOG.md with the release date and version.
- Review README.md, SECURITY.md, architecture documentation, dependencies, and Python compatibility.

## Validate

- Update project.version in pyproject.toml only when a release is approved.
- Run ruff check ., pytest -q, and git diff --check.
- Build distributions using python -m build --outdir dist.
- Verify wheel and source metadata, MIT license, dashboard assets, and source documentation.
- Install both artifacts into separate clean virtual environments. Verify authmatrix version, authmatrix --help, and dashboard assets.
- Confirm Python CI, packaging CI, Docker build, and Compose runtime checks pass.

## Publish

- Merge approved release changes into main.
- Verify the release commit and clean worktree.
- Create an annotated vX.Y.Z tag and push it.
- Create a GitHub Release using the matching changelog section.
- Attach verified distributions where appropriate.
- Publish to PyPI only after explicit approval and secure publishing configuration.
- Never commit credentials or overwrite a published tag.

## Post-release

- Verify the GitHub Release tag, commit, and distribution files.
- If PyPI publication was approved, install the published version in a clean environment and verify the CLI and dashboard assets.
- Document fixes in the changelog and issue a new version rather than replacing published artifacts.

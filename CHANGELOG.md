# Changelog

All notable changes to this project are documented here.

Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning: [SemVer](https://semver.org/).

## [Unreleased]

### Added
- GitHub release workflow: pushing a `v*` tag builds the sdist and wheel, then
  creates or updates the release with both artifacts.

## [0.1.0] - 2026-11-09

### Added
- First packaged release: `pyproject.toml`, the `mcp-scan` console script,
  `.pre-commit-hooks.yaml` and `SECURITY.md`.
- Install with `pipx install git+https://github.com/7sh1d0w7x/mcp-tool-scanner`.

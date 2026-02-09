# Changelog

All notable changes to Cepheus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] - 2026-02-09

### Added

#### Cross-Tool Integration
- `--from-nubicustos` option on the `analyze` command for cloud context enrichment
- Nubicustos container inventory import with cloud metadata preservation
- Cloud context fields added to escape chain analysis results

## [0.2.0] - 2026-01-28

### Added
- Initial release
- POSIX shell enumerator for container security posture collection
- Python analysis engine with 56 escape techniques across 6 categories
- 12 kernel CVE correlations (CVE-2022-0185 through CVE-2025-21756)
- Combinatorial chain analysis with weighted scoring
- PoC command generation for all techniques
- Multiple output formats: terminal, JSON, HTML, MITRE ATT&CK Navigator
- Optional LLM enrichment via LiteLLM
- Posture diff command for before/after comparison

[Unreleased]: https://github.com/Su1ph3r/Cepheus/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/Su1ph3r/Cepheus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/Su1ph3r/Cepheus/releases/tag/v0.2.0

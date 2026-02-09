# Contributing to Cepheus

Contributions are welcome! Here's how to get started.

## Development Setup

```bash
# Clone the repo
git clone https://github.com/su1ph3r/Cepheus.git
cd Cepheus

# Create a virtual environment (Python 3.11+)
python3.11 -m venv .venv
source .venv/bin/activate

# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest
```

## Adding a New Escape Technique

Cepheus uses a declarative technique database. To add a new technique:

1. **Define the technique** in `src/cepheus/engine/technique_db.py`:
   - Choose the appropriate `TechniqueCategory`
   - Set `Severity` based on impact (critical = full host root)
   - Write `Prerequisite` checks using the DSL (see below)
   - Include MITRE ATT&CK mappings and references

2. **Add a PoC template** in `src/cepheus/engine/poc_templates.py`:
   - Use `{placeholder}` syntax for dynamic values
   - Templates render safely via `SafeFormatDict` (missing keys stay as `{key}`)

3. **Add combinatorial pairings** (if applicable) in `src/cepheus/engine/chainer.py`:
   - Update `_is_useful_pairing()` if the technique chains with info-disclosure techniques

4. **Write tests** in `tests/test_engine/`:
   - Test prerequisite matching with a sample posture
   - Test that the technique appears in analysis results

### Prerequisite DSL Reference

| check_type | Description | Example value |
|---|---|---|
| `contains` | List contains value | `"CAP_SYS_ADMIN"` |
| `equals` | Exact match | `true` |
| `not_equals` | Not equal | `"strict"` |
| `gte` / `lte` | Numeric comparison | `2` |
| `kernel_gte` / `kernel_lte` | Kernel version comparison | `"5.8.0"` |
| `kernel_between` | Kernel version range | `["5.8.0", "5.16.0"]` |
| `exists` | Field is not None | `true` |
| `not_empty` | List is non-empty | `true` |
| `regex` | Regex match | `"^/pause"` |
| `version_lte` | Semver version comparison (<=) | `"1.1.12"` |

## Code Style

- Python 3.11+, type hints everywhere
- Line length: 120 characters (configured in `pyproject.toml`)
- Use Pydantic models for data structures
- Keep functions focused — one responsibility per function

## Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=cepheus --cov-report=term-missing

# Run specific test file
pytest tests/test_engine/test_matcher.py
```

All PRs must maintain or improve test coverage. The test suite currently has 144 tests.

## Pull Request Process

1. Fork the repo and create a feature branch
2. Write tests for new functionality
3. Ensure all tests pass (`pytest`)
4. Submit a PR with a clear description of the change

# Contributing to BARAQ

Thank you for considering contributing to BARAQ. This document outlines how to
contribute code, documentation, and security feedback in a way that keeps the
project maintainable and the community healthy.

## Table of contents

- [Code of conduct](#code-of-conduct)
- [Ways to contribute](#ways-to-contribute)
- [Getting started](#getting-started)
- [Development workflow](#development-workflow)
- [Branching and pull requests](#branching-and-pull-requests)
- [Commit conventions](#commit-conventions)
- [Code style](#code-style)
- [Testing](#testing)
- [Documentation](#documentation)
- [AI-assisted contributions](#ai-assisted-contributions)
- [Security disclosures](#security-disclosures)

## Code of conduct

Be respectful, constructive, and inclusive. Harassment or hostile behavior of
any kind is not tolerated. Personal disagreements belong in a private channel,
not in issue threads or pull request reviews.

## Ways to contribute

- Reporting bugs or security issues (see [Security disclosures](#security-disclosures))
- Suggesting features or improvements
- Writing or improving documentation
- Submitting code fixes or new detection/collector modules
- Reviewing open pull requests

## Getting started

```powershell
# 1. Clone the repository
git clone https://github.com/natahanjr/BARAQ.git
cd BARAQ

# 2. Create and activate a virtual environment
python -m venv venv
.\venv\Scripts\Activate.ps1

# 3. Install dependencies
pip install -r requirements.txt

# 4. Start PostgreSQL and the application
.\start.bat
```

The project requires PostgreSQL 14+ and Python 3.13+. See
[`README.md`](README.md) and [`documentation/`](documentation/) for platform
details, including the Linux collector and Windows service setup.

## Development workflow

1. Pick an issue or propose a feature before writing code.
2. Create a dedicated branch from `main`.
3. Implement your change with tests.
4. Run the full test suite locally (see [Testing](#testing)).
5. Open a pull request referencing the issue.

## Branching and pull requests

- Branch naming: `feature/<short-description>`, `fix/<short-description>`,
  `infra/<short-description>`, or `docs/<short-description>`.
- PRs must target `main`.
- Keep PRs focused: one logical change per PR.
- Update the relevant documentation when behavior changes.
- The PR description should explain the *why*, not just the *what*.

## Commit conventions

BARAQ uses conventional commit prefixes:

| Prefix      | Purpose                              |
|-------------|--------------------------------------|
| `Feat:`     | New capability or detection rule     |
| `Fix:`      | Bug fix                              |
| `Refactor:` | Code restructuring, no behavior change |
| `Infra:`    | CI, deployment, tooling, security    |
| `Data:`     | Database migrations or data changes  |
| `Docs:`     | Documentation only                   |
| `WIP:`      | Work in progress (never on `main`)   |

Example: `Feat: add Windows Defender exclusion detection`

## Code style

- Python: follow PEP 8, 100-character lines, type hints on public functions.
- Do **not** add comments unless they explain non-obvious reasoning.
- Frontend: match the existing React/JSX conventions.
- Never commit secrets, `.env` files, private keys, or vault data.

## Testing

All changes must keep the suite green:

```powershell
venv\Scripts\python -m pytest tests -q
```

New detection logic should include a fixture in `tests/fixtures.py` plus an
assertion that the expected alert is produced. When changing database schema,
add an Alembic migration and a test in `tests/test_migrations.py`.

The test suite currently has **1,300+ tests** covering detection rules, API
endpoints, collectors, pipeline, ML, threat intel, SOAR actions, data export,
authentication, and evaluation framework.

## Documentation

User-facing changes must be reflected in `documentation/` and, if relevant,
the `README.md`. Architecture changes should be described in
`documentation/architecture.md`.

## AI-assisted contributions

AI assistants (including Claude, ChatGPT, Copilot, and similar tools) are
welcome as development aids, with the following requirements:

1. **Disclose it.** Mention in the PR description when AI was used to generate
   or significantly modify code, and with which tool.
2. **You are responsible.** AI-generated code must be reviewed, understood,
   and verified by the human author before submission. Submitting code you do
   not understand is not acceptable.
3. **Test it.** AI-generated changes must pass the full test suite and include
   tests just like hand-written code.
4. **No proprietary input.** Do not paste code or data from closed-source,
   proprietary, or licensed sources unless you are certain of the license.
5. **License compliance.** All contributions (including AI-assisted) are
   licensed to the project under the MIT License, as stated in the PR
   submission process.

## Security disclosures

Do **not** report security vulnerabilities in public issues. Email the
maintainers directly or follow the process in [`SECURITY.md`](SECURITY.md).

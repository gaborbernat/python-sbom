# Contributing

Open a [GitHub issue](https://github.com/tox-dev/python-sbom/issues) for a bug or feature request. For a security
report, use the [private reporting process](.github/SECURITY.md). Submit code and documentation changes in a pull
request against `main`. The [contributor guide](https://python-sbom.readthedocs.io/en/latest/contributing.html)
describes the build guarantees and changelog requirements.

## Tests

Add a test for every new feature and bug fix. A change without a test needs a reason in the pull request description.

Run `tox r -e 3.14` for the main test suite, `tox r -m examples` for the backend integrations, and `tox r -e fix,type`
for formatting, linting, and type checks. CI runs these checks on pull requests. On Linux x86-64, `tox r -e fuzz` checks
generated CycloneDX links against the IRI format using Atheris on CPython 3.13.

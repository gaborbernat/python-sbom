from __future__ import annotations

import sys
from typing import Final
from urllib.parse import unquote

import atheris
from jsonschema_rs import Draft7Validator

with atheris.instrument_imports():
    from python_sbom._model._iri import iri_reference

_IRI: Final[Draft7Validator] = Draft7Validator({"type": "string", "format": "iri-reference"}, validate_formats=True)


def check_fragment(data: bytes) -> None:
    text = data.decode("utf-8", errors="replace")
    # A literal percent in the fragment must survive one round of URL decoding.
    reference = iri_reference(f"https://example.org/#{text.replace('%', '%25')}")
    _IRI.validate(reference)
    assert reference is not None
    assert unquote(reference) == f"https://example.org/#{text}"


if __name__ == "__main__":
    atheris.Setup(sys.argv, check_fragment)
    atheris.Fuzz()

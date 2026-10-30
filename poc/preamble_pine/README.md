# Legacy PREAMBLE VDAF (PINE variant)

This directory holds an earlier draft of the PREAMBLE reference implementation
which supports verifying an L2-norm bound on the nonzero block. It will be
merged to the root reference implementation in a future version.

## Requires SageMath

`vdaf_poc` at `-11` imports SageMath (`from sage.all import GF, PolynomialRing`
in `vdaf_poc/field.py`)

## Running

Create a virtual environment on top of Sage's Python, so Sage stays importable,
and install the pinned dependencies from `pyproject.toml`:

```
sage -python -m venv --system-site-packages .venv
.venv/bin/python -m pip install pycryptodomex \
    "vdaf_poc @ git+https://github.com/cfrg/draft-irtf-cfrg-vdaf@draft-irtf-cfrg-vdaf-11#subdirectory=poc" \
    "vdaf_pine_poc @ git+https://github.com/junyechen1996/draft-chen-cfrg-vdaf-pine@junyec/split-api#subdirectory=poc"
```

Run the tests and generate test vectors from this directory:

```
.venv/bin/python -m unittest discover -s .
.venv/bin/python gen_test_vec.py
```

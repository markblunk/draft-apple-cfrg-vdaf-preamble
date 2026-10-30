# PREAMBLE VDAF reference implementation

This directory contains a reference implementation of the PREAMBLE VDAF
([eprint 2025/490](https://eprint.iacr.org/2025/490)), built on the VDAF
framework of
[draft-irtf-cfrg-vdaf](https://datatracker.ietf.org/doc/draft-irtf-cfrg-vdaf/).
It is not intended for production use: the code is not optimized for
performance or resistance to side-channel attacks. Its primary purpose is to
generate test vectors.

## Installation

This code requires Python 3.12 or later to run. It depends on
[`vdaf_poc`](https://github.com/cfrg/draft-irtf-cfrg-vdaf/tree/main/poc), pinned
in `pyproject.toml` to tag `draft-irtf-cfrg-vdaf-18`. To install it, run:

```
python -m pip install "vdaf_poc @ git+https://github.com/cfrg/draft-irtf-cfrg-vdaf@draft-irtf-cfrg-vdaf-18#subdirectory=poc"
```

## Development

To type check, you'll first need to install [mypy](https://mypy-lang.org/):

```
python -m pip install mypy==1.12.0
```

To run unit tests, from this directory:

```
python -m unittest
```

To type check:

```
python -m mypy preamble.py vdpf.py dst.py
```

## Generating test vectors

To generate test vectors, run:

```
python gen_test_vec.py
```

The vectors are written to `test_vec/{VERSION}/`, where `VERSION` is the
contents of the file `VERSION`. Users can also specify a custom path to
generate the test vectors in environment variable `TEST_VECTOR_PATH`:

```
TEST_VECTOR_PATH=path/to/test_vec python gen_test_vec.py
```

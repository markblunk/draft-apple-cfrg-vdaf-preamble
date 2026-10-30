"""
Domain separation tags for all XOF usages, collected all in one place in order
to make it easier to check that they're all distinct.
"""

from vdaf_poc.common import byte, to_be_bytes

# The version of this document. This should be `0` until the document
# gets adopted, at which point this should be synchronized with the
# latest wire-breaking working group draft.
VERSION: int = 0

# Algorithm class byte (fixed to 0).
ALG_CLASS: int = 0

# Preamble VDAF's XOF usage:
# We reuse all Prio3's usages (1-7), and use additional usage codes of our
# own. Make sure they use distinct values from the ones in Prio3.

RESERVED_FOR_PINE = (8, 9, 10)
# Preamble one-block sparse DPF XOF usage:
# We use it to expand the PRG seeds for internal nodes.
USAGE_EXTEND = 11
# We use it to expand the leaf node's PRG seed to a list of field elements
# and proof bytes.
USAGE_CONVERT = 12
# Verify one-hotness in each DPF.
USAGE_ONEHOT_CHECK = 13

def dst_alg(usage: int, algorithm_id: int, ctx: bytes) -> bytes:
    """
    Format the domain separation tag for `usage`, bound to the application
    context `ctx`. Same layout as `vdaf_poc.vdaf.Vdaf.domain_separation_tag()`
    (fixed-width prefix, then `ctx`), except that the version byte is this
    document's `VERSION` rather than `vdaf_poc.common.VERSION`.
    """
    assert usage in range(14)
    assert algorithm_id in range(2 ** 32)
    return byte(VERSION) \
        + byte(ALG_CLASS) \
        + to_be_bytes(algorithm_id, 4) \
        + to_be_bytes(usage, 2) \
        + ctx

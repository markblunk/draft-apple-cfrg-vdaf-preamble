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
# We reuse all Prio3's usages, and use additional usage passed to domain
# separation tag to derive wraparound joint randomness for PINE FLP.
# Make sure they use distinct values from the ones in Prio3.
# Used to derive the wraparound joint randomness field elements from the Xof.
USAGE_WR_JOINT_RANDOMNESS = 8
# Used to derive the wraparound joint randomness seed from the parts.
USAGE_WR_JOINT_RAND_SEED = 9
# Used to derive each wraparound joint randomness seed part.
USAGE_WR_JOINT_RAND_PART = 10
# Preamble one-block sparse DPF XOF usage:
# We use it to expand the PRG seeds for internal nodes.
USAGE_EXTEND = 11
# We use it to expand the leaf node's PRG seed to a list of field elements
# and proof bytes.
USAGE_CONVERT = 12
# Verify one-hotness in each DPF.
USAGE_ONEHOT_CHECK = 13

def dst(usage: int) -> bytes:
    assert usage in range(14)
    return b'preamble' + byte(VERSION) + byte(usage)


def dst_alg(usage: int, algorithm_id: int) -> bytes:
    assert usage in range(14)
    assert algorithm_id in range(2 ** 32)
    return byte(VERSION) \
        + byte(ALG_CLASS) \
        + to_be_bytes(algorithm_id, 4) \
        + to_be_bytes(usage, 2)

import copy
import unittest
from typing import Any

from vdaf_poc.common import gen_rand
from vdaf_poc.field import Field64
from vdaf_poc.flp_bbcggi19 import Count, MultihotCountVec
from vdaf_poc.test_utils import TestVdaf

from preamble import (MULTIHOT_COUNT_VEC_ALGORITHM_ID, Preamble,
                      PreambleCount, PreambleMeasurement,
                      PreambleL1BoundSum, PreambleMultihotCountVec,
                      PreamblePublicShare, PreambleSumVec)

# A note on the shape of these tests, which the FLP fixes at both ends.
#
# A measurement is `(block_index, block_content)`, and `block_content`
# is a measurement for the FLP's circuit rather than field elements:
# `shard()` calls `flp.encode()` on it. Both variants take a vector of
# exactly `block_size` values, as a block of `block_size > 1`
# coordinates should. What the VDPF carries per block is longer,
# `flp.MEAS_LEN`: the multihot circuit appends the weight the Client
# reports, and sum-vec bit-decomposes each coordinate.
#
# Symmetrically, the aggregate result is one `flp.decode()` output per
# block, in leaf order -- a list of per-block results, not one flat vector.


class TestPreambleCount(TestVdaf):
    """
    Exercises `Preamble` over the Prio3 count circuit: `block_size` is
    necessarily 1, and a block's content is a bare 0 or 1.
    """

    def test_single_block(self):
        p = PreambleCount(field=Field64, dimension=1)
        self.assertEqual(p.vdpf.leaf_size, 1)
        self.run_vdaf_test(
            p,
            None,
            [((), 1), ((), 0), ((), 1)],
            [2]
        )

    def test_branching_vdpf(self):
        p = PreambleCount(field=Field64, dimension=4)
        self.assertEqual(p.vdpf.num_leaf_nodes, 4)
        self.run_vdaf_test(
            p,
            None,
            [
                ((False, True), 1),
                ((True, False), 1),
                ((True, True), 1),
                ((True, True), 1),
            ],
            [0, 1, 1, 2]
        )


class TestPreambleMultihotCountVec(TestVdaf):
    """
    Exercises `Preamble` over the Prio3 multihot-count-vector circuit: each
    Client submits a vector of counters with at most `max_weight` of them
    set, and the circuit checks against the weight the Client reports
    in the block's trailing bits.
    """

    def test_single_super_block(self):
        # A block of 3 counters, and one block, so the whole vector is the
        # Client's block. `max_weight == 1` takes one bit to report, so the
        # block the VDPF carries is 4 elements wide.
        p = PreambleMultihotCountVec(field=Field64,
                                     dimension=3,
                                     block_size=3,
                                     max_weight=1,
                                     chunk_length=2)
        self.assertEqual(p.vdpf.leaf_size, 4)
        self.run_vdaf_test(
            p,
            None,
            [
                ((), [1, 0, 0]),
                ((), [0, 1, 0]),
                ((), [1, 0, 0]),
            ],
            [[2, 1, 0]]
        )

    def test_branching_vdpf(self):
        # The VDPF tree here has 4 leaves. The block-index bits only
        # affect which block's aggregate a Client contributes to.
        p = PreambleMultihotCountVec(field=Field64,
                                     dimension=12,
                                     block_size=3,
                                     max_weight=1,
                                     chunk_length=2)
        self.run_vdaf_test(
            p,
            None,
            [
                ((False, True), [1, 0, 0]),
                ((True, False), [0, 1, 0]),
                ((True, True), [0, 1, 0]),
            ],
            [[0, 0, 0], [1, 0, 0], [0, 1, 0], [0, 1, 0]]
        )

    def test_multiple_counters_set(self):
        # `max_weight == 2` needs 2 bits of reported weight, so a
        # block of 3 counters is 5 elements wide in the VDPF. The
        # tree here has 4 leaves.
        p = PreambleMultihotCountVec(field=Field64,
                                     dimension=12,
                                     block_size=3,
                                     max_weight=2,
                                     chunk_length=2)
        self.assertEqual(p.vdpf.num_leaf_nodes, 4)
        self.assertEqual(p.vdpf.leaf_size, 5)
        self.assertEqual(p.output_len, 12)
        self.run_vdaf_test(
            p,
            None,
            [
                ((False, False), [1, 1, 0]),
                ((True, True), [0, 1, 1]),
                ((True, True), [1, 0, 0]),
            ],
            [[1, 1, 0], [0, 0, 0], [0, 0, 0], [1, 1, 1]]
        )


class TestPreambleSumVec(TestVdaf):
    """
    Exercises `Preamble` over the Prio3 sum-vec circuit with `bits == 1`,
    where the encoding is the identity and a block's coordinates are its
    bits.
    """

    def test_single_super_block(self):
        p = PreambleSumVec(field=Field64,
                          dimension=4,
                          block_size=4,
                          chunk_length=2)
        self.run_vdaf_test(
            p,
            None,
            [
                ((), [1, 0, 1, 0]),
                ((), [1, 1, 0, 0]),
                ((), [0, 0, 0, 1]),
            ],
            [[2, 1, 1, 1]]
        )

    def test_branching_vdpf(self):
        p = PreambleSumVec(field=Field64,
                          dimension=8,
                          block_size=2,
                          chunk_length=2)
        self.run_vdaf_test(
            p,
            None,
            [
                ((False, True), [1, 1]),
                ((True, False), [0, 1]),
                ((True, True), [1, 1]),
            ],
            [[0, 0], [1, 1], [0, 1], [1, 1]]
        )


class TestPreambleL1BoundSum(TestVdaf):

    def test_single_super_block(self):
        p = PreambleL1BoundSum(field=Field64, dimension=3, block_size=3,
                               max_value=6, chunk_length=3)
        self.run_vdaf_test(
            p,
            None,
            [
                ((), [1, 2, 3]),
                ((), [6, 0, 0]),
                ((), [0, 0, 0]),
            ],
            [[7, 2, 3]]
        )

    def test_branching_vdpf(self):
        p = PreambleL1BoundSum(field=Field64, dimension=8, block_size=2,
                               max_value=5, chunk_length=2)
        self.run_vdaf_test(
            p,
            None,
            [
                ((False, True), [5, 0]),
                ((True, False), [2, 3]),
                ((True, True), [1, 1]),
                ((True, False), [0, 4]),
            ],
            [[0, 0], [5, 0], [2, 7], [1, 1]]
        )

    def test_rejects_sum_above_bound(self):
        p = PreambleL1BoundSum(field=Field64, dimension=2, block_size=2,
                               max_value=5, chunk_length=2)
        with self.assertRaises(ValueError):
            p.shard(b"ctx", ((False,), [3, 3]), gen_rand(p.NONCE_SIZE),
                    gen_rand(p.RAND_SIZE))


class TestPreambleMultiProof(TestVdaf):
    """
    Exercises `num_proofs > 1` for both variants.
    """

    def test_multihot_count_vec(self):
        p = PreambleMultihotCountVec(field=Field64,
                                     dimension=12,
                                     block_size=3,
                                     max_weight=1,
                                     chunk_length=2,
                                     num_proofs=3)
        self.run_vdaf_test(
            p,
            None,
            [
                ((False, True), [1, 0, 0]),
                ((True, False), [0, 1, 0]),
                ((True, True), [0, 1, 0]),
            ],
            [[0, 0, 0], [1, 0, 0], [0, 1, 0], [0, 1, 0]]
        )

    def test_sum_vec(self):
        p = PreambleSumVec(field=Field64,
                          dimension=8,
                          block_size=2,
                          chunk_length=2,
                          num_proofs=3)
        self.run_vdaf_test(
            p,
            None,
            [
                ((False, True), [1, 1]),
                ((True, False), [0, 1]),
                ((True, True), [1, 1]),
            ],
            [[0, 0], [1, 1], [0, 1], [1, 1]]
        )


class TestPreambleSumVecWideCoordinates(TestVdaf):
    """
    Exercises `bits > 1`, i.e. a second circuit where `flp.MEAS_LEN`
    (the block's encoded length) and `flp.OUTPUT_LEN` (what it
    aggregates to) differ, so it also covers the per-block
    `flp.truncate()` in `verify_init`.

    """

    def test_sums_coordinates_in_range(self):
        # `block_size` is the coordinate count, 2, and the VDPF block
        # is twice that: 2 coordinates x 2 bits. The tree has 2
        # leaves, so the aggregate is 2 blocks x 2 coordinates.
        p = PreambleSumVec(field=Field64,
                          dimension=4,
                          block_size=2,
                          chunk_length=2,
                          bits=2)
        self.assertEqual(p.dimension, 4)
        self.assertEqual(p.vdpf.leaf_size, 4)
        self.assertEqual(p.output_len, 4)
        # A coordinate's sum may leave `[0, 2^bits)` -- the bound is on
        # what each Client submits, not on the aggregate.
        self.run_vdaf_test(
            p,
            None,
            [
                ((False,), [3, 1]),
                ((False,), [1, 2]),
                ((True,), [2, 3]),
            ],
            [[4, 3], [2, 3]]
        )

    def test_multi_proof(self):
        p = PreambleSumVec(field=Field64,
                          dimension=4,
                          block_size=2,
                          chunk_length=2,
                          bits=2,
                          num_proofs=3)
        self.run_vdaf_test(
            p,
            None,
            [
                ((False,), [3, 3]),
                ((True,), [0, 1]),
            ],
            [[3, 3], [0, 1]]
        )


class DishonestBlockValid(MultihotCountVec[Field64]):
    """
    A multihot validity circuit whose `encode()` ignores the Client's
    measurement and returns a fixed block.

    The circuit's weight check compares the counters against the
    weight reported in the block's trailing bits, and an honest
    `encode()` computes those bits from those counters, so no
    measurement can put the two in disagreement. Everything after
    `encode()` here is honest, including the proof. The proof is a
    valid proof *of an invalid statement*, so rejecting it is the
    FLP's soundness.
    """

    def __init__(self, block: list[int], length: int, max_weight: int):
        super().__init__(Field64, length, max_weight, 2)
        self.block = block

    def encode(self, _measurement: Any) -> list[Field64]:
        return [Field64(x) for x in self.block]


class UnusedJointRandCount(Count[Field64]):
    JOINT_RAND_LEN = 1


class RawMultihotPreamble(Preamble):
    ID = MULTIHOT_COUNT_VEC_ALGORITHM_ID


class TestPreambleRejects(unittest.TestCase):
    """
    Negative tests. `run_vdaf` has no way to assert that preparation fails,
    so these drive the lifecycle by hand as far as `verifier_shares_to_message`,
    which is where both the FLP's decision and the one-hot check are made.

    Because `shard()` encodes the block, an invalid block is caught in one of
    two quite different places, and the tests below are split accordingly. A
    measurement that the circuit's `encode()` refuses fails on the Client,
    before any share exists; a block that encodes but does not satisfy the
    circuit fails at an Aggregator. The multihot circuit reaches the second
    case from an honest measurement, because `encode()` range-checks
    nothing; reaching it with a *consistent* proof over a block no honest
    measurement encodes to takes a dishonest Client, hence
    `DishonestBlockValid`.
    """

    def prepare(self,
                vdaf: Preamble,
                measurement: PreambleMeasurement,
                tamper=None,
                tamper_public_share=None,
                shard_ctx: bytes = b"",
                prep_ctx: bytes = b"") -> None:
        """
        Run `shard` -> `verify_init` x2 -> `verifier_shares_to_message` ->
        `verify_next` x2, optionally tampering with the input shares or the
        public share in between. Both Aggregators are handed the *same*
        public share object, as `run_vdaf` does.
        """
        nonce = gen_rand(vdaf.NONCE_SIZE)
        verify_key = gen_rand(vdaf.VERIFY_KEY_SIZE)
        rand = gen_rand(vdaf.RAND_SIZE)
        (public_share, input_shares) = vdaf.shard(
            shard_ctx, measurement, nonce, rand)
        if tamper is not None:
            tamper(input_shares)
        if tamper_public_share is not None:
            tamper_public_share(public_share)
        prep = [
            vdaf.verify_init(verify_key, prep_ctx, j, None, nonce,
                           public_share, input_shares[j])
            for j in range(vdaf.SHARES)
        ]
        verifier_message = vdaf.verifier_shares_to_message(
            prep_ctx, None, [prep_share for (_, prep_share) in prep])
        for (verify_state, _) in prep:
            vdaf.verify_next(prep_ctx, verify_state, verifier_message)

    def multihot(self, **kwargs) -> Preamble:
        """A 3-counter, weight-2 variant over a 2-leaf tree."""
        args: dict[str, Any] = dict(dimension=6, block_size=3, max_weight=2,
                                    chunk_length=2)
        args.update(kwargs)
        return PreambleMultihotCountVec(field=Field64, **args)

    def test_accepts_valid_block(self):
        # Guards the negative tests below: the same path must accept a
        # valid measurement, or they would prove nothing.
        self.prepare(self.multihot(), ((True,), [1, 1, 0]))

    def test_rejects_counter_above_one(self):
        # A counter outside {0, 1}. The Client's `encode()` does not
        # range-check the counters, so this block is built and shared, and
        # it is an Aggregator that rejects it.
        with self.assertRaisesRegex(ValueError, "Decision function failed"):
            self.prepare(self.multihot(), ((True,), [2, 0, 0]))

    def test_rejects_weight_above_max(self):
        # 3 counters set where `max_weight` is 2. The weight no longer fits
        # in the block's reported-weight bits, so `encode()` refuses it on
        # the Client.
        with self.assertRaisesRegex(ValueError, "measurement is too large"):
            self.prepare(self.multihot(), ((True,), [1, 1, 1]))

    def test_rejects_dishonestly_reported_weight(self):
        # 3 counters set, but the block's trailing bits report a weight of
        # 2: they encode `offset + 2 == 3` as [1, 1], LSB first. Only a
        # dishonest Client can build this, and only the circuit's weight
        # check catches it.
        valid = DishonestBlockValid([1, 1, 1, 1, 1], length=3, max_weight=2)
        p = RawMultihotPreamble(Field64, 6, 3, valid, num_proofs=1)
        p.test_vec_name = 'PreambleDishonest'
        with self.assertRaisesRegex(ValueError, "Decision function failed"):
            self.prepare(p, ((True,), [1, 0, 0]))

    def test_rejects_coordinate_out_of_range(self):
        p = PreambleSumVec(field=Field64,
                          dimension=4,
                          block_size=2,
                          chunk_length=2,
                          bits=2)
        # A coordinate that does not fit in `bits`. The sum-vec circuit
        # does range-check its measurement, so this fails on the Client.
        with self.assertRaisesRegex(ValueError, "out of range"):
            self.prepare(p, ((False,), [4, 0]))

    def test_rejects_block_content_of_wrong_length(self):
        # The block holds a fixed number of counters or coordinates, and it
        # is the circuit that turns them into a block, so a content of the
        # wrong length is the circuit's to reject -- with its own message.
        cases = [
            (self.multihot(), [1, 1], "invalid Client measurement length"),
            (self.multihot(), [1, 1, 0, 0], "invalid Client measurement"),
            (PreambleSumVec(field=Field64, dimension=4, block_size=2,
                          chunk_length=2, bits=2),
             [1], "incorrect measurement length"),
        ]
        for (p, block_content, message) in cases:
            with self.subTest(block_content=block_content):
                with self.assertRaisesRegex(ValueError, message):
                    self.prepare(p, ((False,), block_content))

    def test_rejects_tampered_proof_share(self):
        def tamper(input_shares):
            # The Leader's proofs share is a vector of field elements; the
            # Helper's is a seed. Corrupt one element of the Leader's.
            proof_share = input_shares[0].proof_share
            proof_share[0] += Field64(1)

        with self.assertRaises(ValueError):
            self.prepare(self.multihot(), ((True,), [1, 1, 0]), tamper)

    def test_rejects_forged_joint_rand_part(self):
        # The Client lies about the Leader's joint randomness part. Only the
        # Helper can notice, and only if the Leader's `verify_init` has not
        # already overwritten the shared public share's copy with the real
        # part.
        def tamper(public_share):
            public_share.joint_rand_parts[0] = bytes(
                len(public_share.joint_rand_parts[0]))

        with self.assertRaisesRegex(ValueError, "Decision function failed"):
            self.prepare(self.multihot(), ((True,), [1, 1, 0]),
                         tamper_public_share=tamper)

    def test_rejects_inconsistent_joint_rand_seed(self):
        p = Preamble(Field64, 4, 1, UnusedJointRandCount(Field64),
                     num_proofs=1)
        p.test_vec_name = 'PreambleUnusedJointRand'
        self.assertGreater(p.flp.JOINT_RAND_LEN, 0)

        # Guard: untampered, the same path accepts.
        self.prepare(p, ((True, False), 1))

        def tamper(public_share):
            public_share.joint_rand_parts[0] = bytes(
                len(public_share.joint_rand_parts[0]))

        with self.assertRaisesRegex(ValueError,
                                    "Inconsistency between the seeds"):
            self.prepare(p, ((True, False), 1), tamper_public_share=tamper)

    def test_accepts_matching_application_context(self):
        self.prepare(self.multihot(), ((True,), [1, 1, 0]),
                     shard_ctx=b"app-A", prep_ctx=b"app-A")

    def test_rejects_mismatched_application_context(self):
        # A report sharded for one application must not prepare under
        # another: every tag binds `ctx`.
        with self.assertRaises(ValueError):
            self.prepare(self.multihot(), ((True,), [1, 1, 0]),
                         shard_ctx=b"app-A", prep_ctx=b"app-B")

    def test_rejects_block_index_of_wrong_length(self):
        p = self.multihot(dimension=12)
        nonce = gen_rand(p.NONCE_SIZE)
        rand = gen_rand(p.RAND_SIZE)
        # The tree has 4 leaves, so the path must be exactly 2 bits: a
        # shorter one would be zero-padded on the high bits and silently
        # select a different block.
        for block_index in [(), (True,), (True, False, True)]:
            with self.subTest(block_index=block_index):
                with self.assertRaises(ValueError):
                    p.shard(b"", (block_index, [1, 1, 0]), nonce, rand)


class TestPreambleBindings(unittest.TestCase):

    CTX = b"bindings"

    def setUp(self):
        # `PreambleSumVec` has `JOINT_RAND_LEN > 0`.
        self.p = PreambleSumVec(field=Field64, dimension=4, block_size=2,
                                chunk_length=2, bits=2)
        self.assertGreater(self.p.flp.JOINT_RAND_LEN, 0)
        self.nonce = gen_rand(self.p.NONCE_SIZE)
        self.verify_key = gen_rand(self.p.VERIFY_KEY_SIZE)
        (self.public_share, self.input_shares) = self.p.shard(
            self.CTX, ((True,), [1, 2]), self.nonce,
            gen_rand(self.p.RAND_SIZE))

    def init(self, agg_id, public_share=None, input_share=None, nonce=None,
             verify_key=None):
        return self.p.verify_init(
            self.verify_key if verify_key is None else verify_key,
            self.CTX, agg_id, None,
            self.nonce if nonce is None else nonce,
            self.public_share if public_share is None else public_share,
            (self.input_shares[agg_id] if input_share is None
             else input_share))

    def flip_cws_byte(self, public_share):
        """A copy of `public_share` whose encoded correction words differ
        from the original in exactly one byte."""
        encoded = bytearray(self.p.vdpf.encode_correction_words(
            public_share.cws))
        encoded[0] ^= 1
        return PreamblePublicShare(
            cws=self.p.vdpf.decode_correction_words(bytes(encoded)),
            joint_rand_parts=list(public_share.joint_rand_parts))

    def test_rejects_tampered_public_share(self):
        tampered = self.flip_cws_byte(self.public_share)
        prep = [self.init(j, public_share=tampered) for j in range(2)]
        with self.assertRaisesRegex(ValueError, "One-hot check failed"):
            message = self.p.verifier_shares_to_message(
                self.CTX, None, [share for (_, share) in prep])
            for (state, _) in prep:
                self.p.verify_next(self.CTX, state, message)

    def test_rejects_tampered_vdpf_seed(self):
        share = copy.deepcopy(self.input_shares[0])
        share.vdpf_seed = bytes([share.vdpf_seed[0] ^ 1]) + share.vdpf_seed[1:]
        prep = [self.init(0, input_share=share), self.init(1)]
        with self.assertRaisesRegex(ValueError, "One-hot check failed"):
            message = self.p.verifier_shares_to_message(
                self.CTX, None, [s for (_, s) in prep])
            for (state, _) in prep:
                self.p.verify_next(self.CTX, state, message)

class TestPreambleParams(unittest.TestCase):
    """
    Parameter validation in `Preamble.__init__`, and in the circuits the
    instantiations build for it. Each case matches the message too: several of
    these arguments are also rejected further down (by the circuit, or by the
    VDPF), so an unqualified `assertRaises` would pass without the check
    under test ever running.
    """

    def make(self, **kwargs) -> Preamble:
        args: dict[str, Any] = dict(dimension=12, block_size=3, max_weight=1,
                                    chunk_length=2)
        args.update(kwargs)
        return PreambleMultihotCountVec(field=Field64, **args)

    def direct(self, dimension: int, block_size: int, **kwargs) -> Preamble:
        """
        Construct a `Preamble` around a fixed 3-counter, weight-1 circuit,
        whose `MEAS_LEN` is 4: 3 counters and 1 bit of reported weight.
        """
        valid: MultihotCountVec[Field64] = MultihotCountVec(Field64, 3, 1, 2)
        args: dict[str, Any] = dict(num_proofs=1)
        args.update(kwargs)
        p = RawMultihotPreamble(Field64, dimension, block_size, valid, **args)
        p.test_vec_name = 'PreambleTest'
        return p

    def test_dimension_must_divide_into_blocks(self):
        with self.assertRaisesRegex(ValueError, "must be a multiple of"):
            self.make(dimension=7, block_size=3)

    def test_block_count_must_be_a_power_of_two(self):
        with self.assertRaisesRegex(ValueError, "must be a power of 2"):
            self.make(dimension=9, block_size=3)

    def test_dimension_must_be_positive(self):
        with self.assertRaisesRegex(ValueError, "Dimension must be positive"):
            self.make(dimension=0)

    def test_block_size_must_be_positive(self):
        with self.assertRaisesRegex(ValueError, "Block size must be positive"):
            self.direct(dimension=8, block_size=0)

    def test_num_proofs_must_be_in_range(self):
        for num_proofs in [0, -1, 256]:
            with self.assertRaisesRegex(ValueError, r"must be in \[1, 256\)"):
                self.make(num_proofs=num_proofs)

    def test_leaf_size_comes_from_the_flp(self):
        # `block_size` is the Client-facing coordinate count and is *not*
        # cross-checked against the circuit -- `Flp` has no constant for how
        # many coordinates its measurement holds, so the VDPF's per-leaf
        # width comes from `flp.MEAS_LEN` alone. Here the two differ: 3
        # counters plus 1 bit of reported weight is a 4-element leaf, and
        # `dimension` still counts the 3.
        p = self.direct(dimension=6, block_size=3)
        self.assertEqual(p.vdpf.leaf_size, 4)
        self.assertEqual(p.vdpf.num_leaf_nodes, 2)
        self.assertEqual(p.output_len, 6)

    def test_max_weight_must_be_positive(self):
        # `max_weight` reaches `MultihotCountVec` untranslated now that
        # `block_size` is its `length`, so the circuit owns both bounds on
        # it.
        with self.assertRaisesRegex(ValueError, "invalid max_weight"):
            self.make(max_weight=0)

    def test_max_weight_must_not_exceed_block_size(self):
        # A weight bound of 2 over a single counter is unsatisfiable.
        with self.assertRaisesRegex(ValueError, "invalid max_weight"):
            self.make(dimension=4, block_size=1, max_weight=2)

    def test_count_has_no_joint_randomness(self):
        # `Count` has `JOINT_RAND_LEN == 0`: no blinds, parts, or seed.
        p = PreambleCount(field=Field64, dimension=4)
        self.assertEqual(p.flp.JOINT_RAND_LEN, 0)
        ctx = b"some context"
        nonce = gen_rand(p.NONCE_SIZE)
        (public_share, input_shares) = p.shard(
            ctx, ((True, False), 1), nonce, gen_rand(p.RAND_SIZE))
        self.assertEqual(public_share.joint_rand_parts, [])
        for share in input_shares:
            self.assertIsNone(share.joint_rand_blind)

    def test_count_rejects_invalid_measurement(self):
        p = PreambleCount(field=Field64, dimension=1)
        with self.assertRaises(ValueError):
            p.shard(b"ctx", ((), 2), gen_rand(p.NONCE_SIZE),
                    gen_rand(p.RAND_SIZE))


if __name__ == '__main__':
    unittest.main()

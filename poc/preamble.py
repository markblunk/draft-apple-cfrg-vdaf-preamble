'''The Preamble VDAF'''

from typing import Any, Generic, Optional, TypeAlias, TypeVar, Union

from vdaf_poc.common import byte, concat, front, vec_add, vec_sub, zeros
from vdaf_poc.flp import Flp
from vdaf_poc.flp_bbcggi19 import Count, FlpBBCGGI19, MultihotCountVec, SumVec, Valid
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.vdaf_prio3 import (USAGE_JOINT_RAND_PART, USAGE_JOINT_RAND_SEED,
                                 USAGE_JOINT_RANDOMNESS, USAGE_PROOF_SHARE,
                                 USAGE_PROVE_RANDOMNESS,
                                 USAGE_QUERY_RANDOMNESS)
from vdaf_poc.xof import Xof, XofTurboShake128

from dst import USAGE_ONEHOT_CHECK, dst_alg
from l1_bound_sum import L1BoundSum
from vdpf import F, PROOF_SIZE, CorrectionWords, Vdpf

# The FLP's measurement and aggregate result types, i.e. those of one
# block: `Preamble` is generic over the underlying FLP, so a block's
# content and a block's aggregate are whatever that FLP's circuit says
# they are.
FLPMeasurement = TypeVar("FLPMeasurement")
FLPResult = TypeVar("FLPResult")

PreambleMeasurement: TypeAlias = tuple[
    # A pair of block index, and the respective block content. The
    # block index is the path through the VDPF tree, MSB first, and
    # must have exactly one bool per tree level (`vdpf.depth`);
    # `shard()` rejects any other length. The block content is a
    # measurement for the FLP's circuit, which `shard()` encodes with
    # `flp.encode()`.
    tuple[bool, ...], FLPMeasurement
]


class PreamblePublicShare(Generic[F]):
    def __init__(self,
                 cws: CorrectionWords[F],
                 joint_rand_parts: list[bytes]):
        """
        :param cws: public share for the one-block sparse DPF.
        :param joint_rand_parts: joint randomness parts, one per
                                 Aggregator; empty if
                                 `flp.JOINT_RAND_LEN == 0`.
        """
        self.cws = cws
        self.joint_rand_parts = joint_rand_parts


class PreambleInputShare(Generic[F]):
    def __init__(self,
                 vdpf_seed: bytes,
                 proof_share: Union[list[F], bytes],
                 joint_rand_blind: Optional[bytes]):
        """One Aggregator's input share.

        :param vdpf_seed: this Aggregator's secret half of the VDPF
                         key.  Evaluating it against the public
                         share's correction words (`vdpf.eval_all()`)
                         yields a share of every block, and the
                         block-wise sum of those is this Aggregator's
                         measurement share for the FLP.  The block's
                         contents reach the Aggregators in the public
                         share's `leaf_cw`, but masked there by the
                         expansions of both parties' on-path leaf
                         seeds, so neither the seed nor the public
                         share reveals the block on its own.
        :param proof_share: share of the proof for the FLP. The Leader
                             holds field elements; the Helper holds a
                             seed it expands with
                             `helper_proof_share()`.
        :param joint_rand_blind: this Aggregator's blind for the joint
                                 randomness the FLP consumes, so it
                                 exists only if
                                 `flp.JOINT_RAND_LEN > 0` (else
                                 `None`).  What it
                                 commits to, though, is VDPF
                                 material: `joint_rand_part()` binds
                                 the nonce, the encoded public share
                                 and `vdpf_seed`, where Prio3 binds
                                 the measurement share.
        """
        self.vdpf_seed = vdpf_seed
        self.proof_share = proof_share
        self.joint_rand_blind = joint_rand_blind


PreambleOutputShare: TypeAlias = list[F]


PreambleAggShare: TypeAlias = list[F]


# One FLP aggregate result per block.
PreambleAggResult: TypeAlias = list[FLPResult]


class PreambleVerifyState(Generic[F]):
    def __init__(self,
                 output_share: PreambleOutputShare[F],
                 corrected_joint_rand_seed: Optional[bytes]):
        """
        :param output_share: output share, i.e., secret share of the original
                             client vector.
        :param corrected_joint_rand_seed: corrected joint randomness seed
                                          computed by the current
                                          aggregator, or `None` if
                                          `flp.JOINT_RAND_LEN == 0`.
        """
        self.output_share = output_share
        self.corrected_joint_rand_seed = corrected_joint_rand_seed


class PreambleVerifierShare(Generic[F]):
    def __init__(self,
                 one_hot_check: bytes,
                 verifiers_share: list[F],
                 joint_rand_part: Optional[bytes]):
        """
        :param one_hot_check: one-hot check by hashing all the proof bytes
                              at the leaf nodes.
        :param verifiers_share: verifiers share computed by the current
                                aggregator.
        :param joint_rand_part: joint randomness part computed by the
                                current aggregator, or `None` if
                                `flp.JOINT_RAND_LEN == 0`.
        """
        self.one_hot_check = one_hot_check
        self.verifiers_share = verifiers_share
        self.joint_rand_part = joint_rand_part


# The joint randomness seed, or `None` if `flp.JOINT_RAND_LEN == 0`.
PreambleVerifierMessage: TypeAlias = Optional[bytes]


class Preamble(
        Generic[FLPMeasurement, FLPResult, F],
        Vdaf[
            PreambleMeasurement[FLPMeasurement],
            None,  # Preamble doesn't use aggregation param.
            PreamblePublicShare[F],
            PreambleInputShare[F],
            PreambleOutputShare[F],
            PreambleAggShare[F],
            PreambleAggResult[FLPResult],
            PreambleVerifyState[F],
            PreambleVerifierShare[F],
            PreambleVerifierMessage,
        ]):

    # Required properties by `Vdaf`:
    NONCE_SIZE = 16
    SHARES = 2
    ROUNDS = 1
    ID: int = 0xFFFFFFFF  # overridden by concrete instantiations
    RAND_SIZE: int  # to be set by constructor
    VERIFY_KEY_SIZE: int  # to be set by constructor
    test_vec_name: str = "Preamble"

    # Other parameters set by constructor.
    field: type[F]
    xof: type[Xof]
    vdpf: Vdpf[F]
    dimension: int
    block_size: int
    output_len: int
    flp: Flp[FLPMeasurement, FLPResult, F]
    PROOFS: int  # Number of proofs, in range `[1, 256)`

    def __init__(self,
                 field: type[F],
                 dimension: int,
                 block_size: int,
                 valid: Valid[FLPMeasurement, FLPResult, F],
                 num_proofs: int,
                 xof: type[Xof] = XofTurboShake128):
        """
        :param field: NTT-friendly finite field
        :param dimension: dimension of the original vector space, i.e. the
                          length of the vector the Client is
                          submitting.
        :param block_size: number of coordinates in one block.
        :param valid: validity circuit for one block's content. If
                      `JOINT_RAND_LEN`==0 , then case no blinds,
                      joint randomness parts or seed check are used.
        :param num_proofs: number of independent copies of the proof to
                           generate and check.
        :param xof: Extendable Output Function.
        """
        flp = FlpBBCGGI19(valid)
        if dimension < 1:
            raise ValueError("Dimension must be positive.")
        if block_size < 1:
            raise ValueError("Block size must be positive.")
        if num_proofs not in range(1, 256):
            raise ValueError("Number of proofs must be in [1, 256).")
        if flp.MEAS_LEN < 1:
            raise ValueError("flp.MEAS_LEN must be positive.")
        if flp.OUTPUT_LEN < 1:
            raise ValueError("flp.OUTPUT_LEN must be positive.")
        self.field = field
        self.xof = xof
        self.flp = flp
        self.PROOFS = num_proofs
        self.dimension = dimension
        self.block_size = block_size
        # The construction requires `dimension == 2^depth *
        # block_size`: the vector divides exactly into blocks, and the
        # blocks fill a complete binary tree depth-many levels.
        if dimension % block_size != 0:
            raise ValueError(
                f"dimension={dimension} must be a multiple of "
                f"block_size={block_size}.")
        num_leaf_nodes = dimension // block_size
        if num_leaf_nodes & (num_leaf_nodes - 1) != 0:
            raise ValueError(
                f"dimension/block_size={num_leaf_nodes} must be a power of "
                f"2 (dimension={dimension}, block_size={block_size}).")
        self.vdpf = Vdpf(
            field=field,
            num_leaf_nodes=num_leaf_nodes,
            leaf_size=flp.MEAS_LEN,
            nonce_size=self.NONCE_SIZE,
            xof=xof,
            algorithm_id=self.ID)
        self.output_len = num_leaf_nodes * flp.OUTPUT_LEN
        self.VERIFY_KEY_SIZE = self.xof.SEED_SIZE
        # The size of randomness is the sum of the randomness the
        # VDPF's `gen()` consumes `self.vdpf.RAND_SIZE = 2 *
        # xof.SEED_SIZE`, as well as `xof.SEED_SIZE` times the sum of
        # the following:
        # - Helper's proof share seed.
        # - One joint randomness seed blind per party.
        # - One prover randomness seed.
        #
        # Helper's proof share seed, prover randomness seed, and -- only if
        # the FLP consumes joint randomness -- one blind per Aggregator.
        self.RAND_SIZE = (self.vdpf.RAND_SIZE +
            (2 + (self.SHARES if flp.JOINT_RAND_LEN > 0 else 0)) *
            self.xof.SEED_SIZE)

    def shard(self,
              ctx: bytes,
              measurement: PreambleMeasurement[FLPMeasurement],
              nonce: bytes,
              rand: bytes,
              ) -> tuple[PreamblePublicShare[F],
                         list[PreambleInputShare[F]]]:
        if len(rand) != self.RAND_SIZE:
            raise ValueError(
                f"randomness has {len(rand)} bytes, expected "
                f"{self.RAND_SIZE}.")
        (block_index, block_content) = measurement

        leader_id = 0
        helper_id = 1

        (leader_vdpf_seed, rand) = front(self.xof.SEED_SIZE, rand)
        (helper_vdpf_seed, rand) = front(self.xof.SEED_SIZE, rand)
        # Helper's proofs share.
        (helper_proof_share_seed, rand) = front(self.xof.SEED_SIZE, rand)
        # Joint randomness seed blinds, only if the FLP consumes joint
        # randomness.
        helper_blind: Optional[bytes] = None
        leader_blind: Optional[bytes] = None
        if self.flp.JOINT_RAND_LEN > 0:
            (helper_blind, rand) = front(self.xof.SEED_SIZE, rand)
            (leader_blind, rand) = front(self.xof.SEED_SIZE, rand)
        # Prover randomness:
        (prove_rand_seed, rand) = front(self.xof.SEED_SIZE, rand)

        # The FLP owns the block's encoding: `block_content` is a
        # measurement for its circuit, and is the encoded form that
        # the VDPF shares. `vdpf.leaf_size` is `flp.MEAS_LEN` by
        # construction, so the encoding is exactly one leaf wide.
        encoded_block = self.flp.encode(block_content)
        assert len(encoded_block) == self.vdpf.leaf_size
        vdpf_rand = leader_vdpf_seed + helper_vdpf_seed
        # The path must name a leaf exactly: one bool per tree level,
        # MSB first.
        if len(block_index) != self.vdpf.depth:
            raise ValueError(
                f"block index has {len(block_index)} bits, expected "
                f"{self.vdpf.depth} (one per level of a "
                f"{self.vdpf.num_leaf_nodes}-leaf tree).")
        leaf_index = 0
        for b in block_index:
            leaf_index = (leaf_index << 1) | int(b)
        (cws, seeds) = self.vdpf.gen(
            leaf_index, encoded_block, ctx, nonce, vdpf_rand)
        leader_vdpf_seed = seeds[leader_id]
        helper_vdpf_seed = seeds[helper_id]
        assert len(rand) == 0

        encoded_cws = self.vdpf.encode_correction_words(cws)

        # Each Aggregator's part binds the nonce, the encoded public
        # share, and its own VDPF seed. Without joint randomness there
        # is nothing to derive, exactly as in Prio3's
        # `shard_without_joint_rand`.
        joint_rand_parts: list[bytes] = []
        joint_rands: list[F] = []
        if self.flp.JOINT_RAND_LEN > 0:
            assert leader_blind is not None and helper_blind is not None
            joint_rand_parts = [
                self.joint_rand_part(ctx, leader_id, leader_blind, nonce,
                                     encoded_cws, leader_vdpf_seed),
                self.joint_rand_part(ctx, helper_id, helper_blind, nonce,
                                     encoded_cws, helper_vdpf_seed),
            ]
            joint_rands = self.joint_rands(
                ctx, self.joint_rand_seed(ctx, joint_rand_parts))

        # Generate each proof and shard it into proof shares.
        prove_rands = self.prove_rands(ctx, prove_rand_seed)
        proofs:list[F] = []
        for _ in range(self.PROOFS):
            (prove_rand, prove_rands) = front(
                self.flp.PROVE_RAND_LEN, prove_rands)
            (joint_rand, joint_rands) = front(
                self.flp.JOINT_RAND_LEN, joint_rands)
            proofs += self.flp.prove(
                encoded_block, prove_rand, joint_rand)

        # Secret-share the proofs into leader's proof share.
        leader_proof_share = vec_sub(
            proofs, self.helper_proof_share(ctx, helper_proof_share_seed)
        )

        return (
            PreamblePublicShare(
                cws=cws,
                joint_rand_parts=joint_rand_parts
            ),
            [
                PreambleInputShare(
                    vdpf_seed=leader_vdpf_seed,
                    proof_share=leader_proof_share,
                    joint_rand_blind=leader_blind
                ),
                PreambleInputShare(
                    vdpf_seed=helper_vdpf_seed,
                    proof_share=helper_proof_share_seed,
                    joint_rand_blind=helper_blind
                )
            ]
        )

    def is_valid(self, agg_param, previous_agg_params):
        """
        Checks if `previous_agg_params` is empty, as input shares in Preamble
        may only be used once.
        """
        return len(previous_agg_params) == 0

    def verify_init(
            self,
            verify_key: bytes,
            ctx: bytes,
            agg_id: int,
            agg_param: None,
            nonce: bytes,
            public_share: PreamblePublicShare[F],
            input_share: PreambleInputShare[F],
    ) -> tuple[PreambleVerifyState[F], PreambleVerifierShare[F]]:
        initial_ctrl_bit = agg_id > 0  # Same used by the client.
        # This Aggregator's share of the Client's whole encoded vector, one
        # block after another -- obtained by locally expanding the compact
        # VDPF share (`input_share.vdpf_seed` plus `public_share.cws`) at
        # every leaf.
        (encoded_vector_share, proof) = self.vdpf.eval_all(
            ctx,
            nonce,
            agg_id,
            input_share.vdpf_seed,
            initial_ctrl_bit,
            public_share.cws,
        )
        assert len(encoded_vector_share) == (
            self.vdpf.num_leaf_nodes * self.vdpf.leaf_size)
        one_hot_check_binder = concat(proof)
        leaf_size = self.vdpf.leaf_size
        encoded_block_share = self.field.zeros(leaf_size)
        for i in range(len(encoded_vector_share)):
            encoded_block_share[i % leaf_size] += encoded_vector_share[i]

        # The output share is the per-block truncation of this Aggregator's
        # share of the encoded vector.
        output_share: list[F] = []
        for block_share in self.blocks(encoded_vector_share, leaf_size):
            output_share += self.flp.truncate(block_share)
        assert len(output_share) == self.output_len

        # Hash all proof bytes at the leaf nodes to check one-hotness.
        one_hot_check = self.xof(
            verify_key,
            dst_alg(USAGE_ONEHOT_CHECK, self.ID, ctx),
            one_hot_check_binder,
        ).next(PROOF_SIZE)

        encoded_cws = self.vdpf.encode_correction_words(public_share.cws)

        # The Leader holds its proofs share as field elements; the Helper
        # holds a seed it expands, exactly as in Prio3.
        proof_share: list[F]
        if agg_id == 0:
            assert isinstance(input_share.proof_share, list)
            proof_share = input_share.proof_share
        else:
            assert isinstance(input_share.proof_share, bytes)
            proof_share = self.helper_proof_share(
                ctx, input_share.proof_share)

        joint_rand_part: Optional[bytes] = None
        corrected_joint_rand_seed: Optional[bytes] = None
        joint_rands: list[F] = []
        if self.flp.JOINT_RAND_LEN > 0:
            assert input_share.joint_rand_blind is not None
            joint_rand_part = self.joint_rand_part(
                ctx,
                agg_id,
                input_share.joint_rand_blind,
                nonce,
                encoded_cws,
                input_share.vdpf_seed,
            )
            # Substitute this Aggregator's own part into a copy: writing
            # it into `public_share` would allow one Aggregator to
            # overwrite a forged part before the other one (sharing the
            # same object) sees it.
            joint_rand_parts = list(public_share.joint_rand_parts)
            joint_rand_parts[agg_id] = joint_rand_part
            corrected_joint_rand_seed = self.joint_rand_seed(
                ctx, joint_rand_parts)
            joint_rands = self.joint_rands(ctx, corrected_joint_rand_seed)

        # Query this party's share of the block, which is the FLP's
        # measurement share, and its share of each proof.
        query_rands = self.query_rands(verify_key, ctx, nonce)
        verifiers_share: list[F] = []
        for _ in range(self.PROOFS):
            (this_proof_share, proof_share) = front(
                self.flp.PROOF_LEN, proof_share)
            (query_rand, query_rands) = front(
                self.flp.QUERY_RAND_LEN, query_rands)
            (joint_rand, joint_rands) = front(
                self.flp.JOINT_RAND_LEN, joint_rands)
            verifiers_share += self.flp.query(
                encoded_block_share,
                this_proof_share,
                query_rand,
                joint_rand,
                self.SHARES,
            )

        return (
            PreambleVerifyState(
                output_share,
                corrected_joint_rand_seed
            ),
            PreambleVerifierShare(
                one_hot_check,
                verifiers_share,
                joint_rand_part
            )
        )

    def verifier_shares_to_message(self,
                            ctx: bytes,
                            agg_param: None,
                            verifier_shares: list[PreambleVerifierShare[F]],
                            ) -> PreambleVerifierMessage:
        assert len(verifier_shares) == self.SHARES
        if verifier_shares[0].one_hot_check != verifier_shares[1].one_hot_check:
            raise ValueError("One-hot check failed")

        # Unshard the verifier shares into the verifier message.
        verifiers = vec_add(verifier_shares[0].verifiers_share,
                            verifier_shares[1].verifiers_share)

        # Verify that each proof is well-formed and the input is valid.
        for _ in range(self.PROOFS):
            (verifier, verifiers) = front(self.flp.VERIFIER_LEN, verifiers)
            if not self.flp.decide(verifier):
                raise ValueError(
                    "Decision function failed after combining all verifier "
                    "shares.")

        if self.flp.JOINT_RAND_LEN == 0:
            return None

        # Combine the joint randomness parts computed by the Aggregators
        # into the true joint randomness seed, which is checked by all
        # Aggregators.
        (part_0, part_1) = (verifier_shares[0].joint_rand_part,
                            verifier_shares[1].joint_rand_part)
        if part_0 is None or part_1 is None:
            raise ValueError("expected joint randomness parts")
        return self.joint_rand_seed(ctx, [part_0, part_1])

    def verify_next(self,
                  ctx: bytes,
                  verify_state: PreambleVerifyState[F],
                  verifier_message: PreambleVerifierMessage,
                  ) -> PreambleOutputShare[F]:
        # Joint randomness seed computed from both Aggregators' parts. Make
        # sure it is consistent with the one computed by this Aggregator.
        # A `None` seed on both sides means no joint randomness.
        if verifier_message != verify_state.corrected_joint_rand_seed:
            raise ValueError("Inconsistency between the seeds.")
        return verify_state.output_share

    def agg_init(self, agg_param: None) -> PreambleAggShare[F]:
        return self.field.zeros(self.output_len)

    def agg_update(
            self,
            agg_param: None,
            agg_share: PreambleAggShare[F],
            out_share: PreambleOutputShare[F],
    ) -> PreambleAggShare[F]:
        return vec_add(agg_share, out_share)

    def merge(
            self,
            agg_param: None,
            agg_shares: list[PreambleAggShare[F]],
    ) -> PreambleAggShare[F]:
        agg = self.agg_init(agg_param)
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)
        return agg

    def encode_agg_param(self, agg_param: None) -> bytes:
        return b""

    def unshard(self,
                agg_param: None,
                agg_shares: list[PreambleAggShare[F]],
                num_measurements: int) -> PreambleAggResult[FLPResult]:
        agg = self.merge(agg_param, agg_shares)
        # The aggregate is one truncated block after another, and each
        # block is decoded by the circuit that validated it -- so the
        # result is one FLP aggregate result per block, in leaf
        # order.
        return [
            self.flp.decode(block, num_measurements)
            for block in self.blocks(agg, self.flp.OUTPUT_LEN)
        ]

    # Helper methods:

    def blocks(self, vec: list[F], block_len: int) -> list[list[F]]:
        """
        Split a flat vector into one slice per block of the vector space, in
        leaf order.

        Both vectors Preamble handles have this shape: the encoded one
        that `vdpf.eval_all()` returns (`block_len == vdpf.leaf_size`)
        and the truncated one that is aggregated (`block_len ==
        flp.OUTPUT_LEN`).  Neither is typed as `list[list[F]]`,
        because a flat vector is what the wire encoding and `vec_add`
        want -- an output share is summed across Clients element-wise,
        and its block boundaries carry no information the shape
        doesn't already fix. So the boundaries live here instead, in
        one place, rather than as index arithmetic at each use.

        """
        expected = self.vdpf.num_leaf_nodes * block_len
        if len(vec) != expected:
            raise ValueError(
                f"expected {expected} field elements "
                f"({self.vdpf.num_leaf_nodes} blocks of {block_len}), got "
                f"{len(vec)}.")
        return [vec[i * block_len:(i + 1) * block_len]
                for i in range(self.vdpf.num_leaf_nodes)]

    def joint_rand_part(self,
                        ctx: bytes,
                        agg_id: int,
                        seed_blind: bytes,
                        nonce: bytes,
                        encoded_public_share: bytes,
                        vdpf_seed: bytes) -> bytes:
        """
        Compute this Aggregator's joint randomness part.

        Preamble has no explicit measurement share to bind: the
        Aggregator's share is a deterministic function of `nonce`,
        `agg_id`, `vdpf_seed`, and the encoded public share, all of
        which are bound below.
        """
        return self.xof.derive_seed(
            seed_blind,
            dst_alg(USAGE_JOINT_RAND_PART, self.ID, ctx),
            byte(agg_id) + nonce + encoded_public_share + vdpf_seed,
        )

    def joint_rand_seed(self,
                        ctx: bytes,
                        joint_rand_parts: list[bytes]) -> bytes:
        """Derive the joint randomness seed from its parts."""
        return self.xof.derive_seed(
            zeros(self.xof.SEED_SIZE),
            dst_alg(USAGE_JOINT_RAND_SEED, self.ID, ctx),
            concat(joint_rand_parts),
        )

    def joint_rands(self, ctx: bytes, joint_rand_seed: bytes) -> list[F]:
        """Derive the joint randomness for each proof from its seed."""
        return self.xof.expand_into_vec(
            self.field,
            joint_rand_seed,
            dst_alg(USAGE_JOINT_RANDOMNESS, self.ID, ctx),
            byte(self.PROOFS),
            self.flp.JOINT_RAND_LEN * self.PROOFS,
        )

    def prove_rands(self, ctx: bytes, prove_rand_seed: bytes) -> list[F]:
        """Derive the prover randomness for each proof from its seed."""
        return self.xof.expand_into_vec(
            self.field,
            prove_rand_seed,
            dst_alg(USAGE_PROVE_RANDOMNESS, self.ID, ctx),
            byte(self.PROOFS),
            self.flp.PROVE_RAND_LEN * self.PROOFS,
        )

    def query_rands(self,
                    verify_key: bytes,
                    ctx: bytes,
                    nonce: bytes) -> list[F]:
        """
        Derive the query randomness for each proof from the verify
        key.
        """
        return self.xof.expand_into_vec(
            self.field,
            verify_key,
            dst_alg(USAGE_QUERY_RANDOMNESS, self.ID, ctx),
            byte(self.PROOFS) + nonce,
            self.flp.QUERY_RAND_LEN * self.PROOFS,
        )

    def helper_proof_share(self,
                           ctx: bytes,
                           proof_share_seed: bytes) -> list[F]:
        """
        Expand helper's seed for proof share into a list of field
        elements.
        """
        return self.xof.expand_into_vec(
            self.field,
            proof_share_seed,
            dst_alg(USAGE_PROOF_SHARE, self.ID, ctx),
            byte(self.PROOFS) + byte(1),
            self.flp.PROOF_LEN * self.PROOFS
        )

    # Methods to generate test vectors:

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec["dimension"] = self.dimension
        test_vec["block_size"] = self.block_size
        keys = ["dimension", "block_size"]
        keys += self.flp.test_vec_set_type_param(test_vec)
        return keys

    # Wire encodings, used by the test vectors. Each `decode_*` rejects
    # trailing bytes, like Prio3's.

    def encode_input_share(self,
                           input_share: PreambleInputShare[F],
                           ) -> bytes:
        encoded = bytes()
        # Encode the VDPF seed
        encoded += input_share.vdpf_seed

        # Encode proofs share
        if isinstance(input_share.proof_share, list):  # Leader
            encoded += self.field.encode_vec(input_share.proof_share)
        else:  # Helper (seed)
            encoded += input_share.proof_share

        # Encode joint randomness blind
        if self.flp.JOINT_RAND_LEN > 0:
            assert input_share.joint_rand_blind is not None
            encoded += input_share.joint_rand_blind

        return encoded

    def decode_input_share(self,
                           agg_id: int,
                           encoded: bytes,
                           ) -> PreambleInputShare[F]:
        (vdpf_seed, encoded) = front(self.vdpf.KEY_SIZE, encoded)
        proof_share: Union[list[F], bytes]
        if agg_id == 0:  # Leader
            (proof_bytes, encoded) = front(
                self.field.ENCODED_SIZE * self.flp.PROOF_LEN * self.PROOFS,
                encoded)
            proof_share = self.field.decode_vec(proof_bytes)
        else:  # Helper (seed)
            (proof_share, encoded) = front(self.xof.SEED_SIZE, encoded)
        joint_rand_blind: Optional[bytes] = None
        if self.flp.JOINT_RAND_LEN > 0:
            (joint_rand_blind, encoded) = front(self.xof.SEED_SIZE, encoded)
        if len(encoded) != 0:
            raise ValueError("input share is too long")
        return PreambleInputShare(vdpf_seed, proof_share, joint_rand_blind)

    def encode_public_share(self,
                            public_share: PreamblePublicShare,
                            ) -> bytes:
        encoded = bytes()
        # Encode the VDPF public share
        encoded += self.vdpf.encode_correction_words(public_share.cws)
        # Encode joint randomness parts
        encoded += concat(public_share.joint_rand_parts)
        return encoded

    def decode_public_share(self, encoded: bytes) -> PreamblePublicShare[F]:
        (cws_bytes, encoded) = front(
            self.vdpf.correction_words_size(), encoded)
        cws = self.vdpf.decode_correction_words(cws_bytes)
        joint_rand_parts = []
        if self.flp.JOINT_RAND_LEN > 0:
            for _ in range(self.SHARES):
                (part, encoded) = front(self.xof.SEED_SIZE, encoded)
                joint_rand_parts.append(part)
        if len(encoded) != 0:
            raise ValueError("public share is too long")
        return PreamblePublicShare(cws, joint_rand_parts)

    def encode_agg_share(self, agg_share: PreambleAggShare[F]) -> bytes:
        return self.field.encode_vec(agg_share)

    def decode_agg_share(self,
                         agg_param: None,
                         encoded: bytes,
                         ) -> PreambleAggShare[F]:
        if len(encoded) != self.field.ENCODED_SIZE * self.output_len:
            raise ValueError("aggregate share has incorrect length")
        return self.field.decode_vec(encoded)

    def encode_out_share(self, out_share: PreambleOutputShare[F]) -> bytes:
        return self.field.encode_vec(out_share)

    def decode_out_share(self,
                         agg_param: None,
                         encoded: bytes,
                         ) -> PreambleOutputShare[F]:
        if len(encoded) != self.field.ENCODED_SIZE * self.output_len:
            raise ValueError("output share has incorrect length")
        return self.field.decode_vec(encoded)

    def decode_agg_param(self, encoded: bytes) -> None:
        if encoded != b"":
            raise ValueError("invalid encoded aggregation parameter")

    def encode_verifier_share(self,
                              verifier_share: PreambleVerifierShare[F],
                              ) -> bytes:
        encoded = bytes()
        # Encode one-hot check
        encoded += verifier_share.one_hot_check
        # Encode verifiers share
        encoded += self.field.encode_vec(verifier_share.verifiers_share)
        # Encode joint randomness part
        if self.flp.JOINT_RAND_LEN > 0:
            assert verifier_share.joint_rand_part is not None
            encoded += verifier_share.joint_rand_part
        return encoded

    def decode_verifier_share(self,
                              verify_state: PreambleVerifyState[F],
                              encoded: bytes,
                              ) -> PreambleVerifierShare[F]:
        (one_hot_check, encoded) = front(PROOF_SIZE, encoded)
        (verifiers_bytes, encoded) = front(
            self.field.ENCODED_SIZE * self.flp.VERIFIER_LEN * self.PROOFS,
            encoded)
        verifiers_share = self.field.decode_vec(verifiers_bytes)
        joint_rand_part: Optional[bytes] = None
        if self.flp.JOINT_RAND_LEN > 0:
            (joint_rand_part, encoded) = front(self.xof.SEED_SIZE, encoded)
        if len(encoded) != 0:
            raise ValueError("verifier share is too long")
        return PreambleVerifierShare(
            one_hot_check, verifiers_share, joint_rand_part)

    def encode_verifier_message(self,
                                verifier_message: PreambleVerifierMessage,
                                ) -> bytes:
        return verifier_message if verifier_message is not None else b""

    def decode_verifier_message(self,
                                verify_state: PreambleVerifyState[F],
                                encoded: bytes,
                                ) -> PreambleVerifierMessage:
        expected = self.xof.SEED_SIZE if self.flp.JOINT_RAND_LEN > 0 else 0
        if len(encoded) != expected:
            raise ValueError("verifier message has incorrect length")
        return encoded if self.flp.JOINT_RAND_LEN > 0 else None


MULTIHOT_COUNT_VEC_ALGORITHM_ID = 0xFFFFFFFE
SUM_VEC_ALGORITHM_ID = 0xFFFFFFFD
COUNT_ALGORITHM_ID = 0xFFFFFFFC
L1_BOUND_SUM_ALGORITHM_ID = 0xFFFFFFFB


class PreambleCount(Preamble[int, int, F]):

    ID = COUNT_ALGORITHM_ID
    test_vec_name = 'PreambleCount'

    def __init__(self,
                 field: type[F],
                 dimension: int,
                 num_proofs: int = 1,
                 xof: type[Xof] = XofTurboShake128):
        super().__init__(field, dimension, 1, Count(field),
                         num_proofs=num_proofs,
                         xof=xof)


class PreambleMultihotCountVec(Preamble[list[bool], list[int], F]):
    ID = MULTIHOT_COUNT_VEC_ALGORITHM_ID
    test_vec_name = 'PreambleMultihotCountVec'

    def __init__(self,
                 field: type[F],
                 dimension: int,
                 block_size: int,
                 max_weight: int,
                 chunk_length: int,
                 num_proofs: int = 1,
                 xof: type[Xof] = XofTurboShake128):
        valid = MultihotCountVec(field, block_size, max_weight, chunk_length)
        super().__init__(field, dimension, block_size, valid,
                         num_proofs=num_proofs,
                         xof=xof)


class PreambleSumVec(Preamble[list[int], list[int], F]):

    ID = SUM_VEC_ALGORITHM_ID
    test_vec_name = 'PreambleSumVec'

    def __init__(self,
                 field: type[F],
                 dimension: int,
                 block_size: int,
                 chunk_length: int,
                 bits: int = 1,
                 num_proofs: int = 1,
                 xof: type[Xof] = XofTurboShake128):
        valid = SumVec(field, block_size, 2 ** bits - 1, chunk_length)
        super().__init__(field, dimension, block_size, valid,
                         num_proofs=num_proofs,
                         xof=xof)
class PreambleL1BoundSum(Preamble[list[int], list[int], F]):
    ID = L1_BOUND_SUM_ALGORITHM_ID
    test_vec_name = 'PreambleL1BoundSum'

    def __init__(self,
                 field: type[F],
                 dimension: int,
                 block_size: int,
                 max_value: int,
                 chunk_length: int,
                 num_proofs: int = 1,
                 xof: type[Xof] = XofTurboShake128):
        valid = L1BoundSum(field, block_size, max_value, chunk_length)
        super().__init__(field, dimension, block_size, valid,
                         num_proofs=num_proofs,
                         xof=xof)

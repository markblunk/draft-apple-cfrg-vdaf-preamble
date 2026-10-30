'''The Preamble VDAF'''

from typing import Any, Generic, TypeAlias, TypeVar, Union

from vdaf_pine_poc.flp_pine import (ALPHA, NUM_WR_CHECKS, NUM_WR_SUCCESSES,
                                    PineValid, construct_circuits)
from vdaf_pine_poc.xof_hmac_sha256_aes128 import XofHmacSha256Aes128
from vdaf_poc.common import byte, concat, front, vec_add, vec_sub, zeros
from vdaf_poc.field import NttField
from vdaf_poc.flp_bbcggi19 import FlpBBCGGI19
from vdaf_poc.vdaf import Vdaf
from vdaf_poc.vdaf_prio3 import (USAGE_JOINT_RAND_PART, USAGE_JOINT_RAND_SEED,
                                 USAGE_JOINT_RANDOMNESS, USAGE_MEAS_SHARE,
                                 USAGE_PROOF_SHARE, USAGE_PROVE_RANDOMNESS,
                                 USAGE_QUERY_RANDOMNESS)
from vdaf_poc.xof import Xof

from dst import (USAGE_ONEHOT_CHECK, USAGE_WR_JOINT_RANDOMNESS,
                 USAGE_WR_JOINT_RAND_PART, USAGE_WR_JOINT_RAND_SEED, dst_alg)
from vidpf_pine import PROOF_SIZE, PreambleOneBlockSparse, OneBlockSparsePublicShare

F = TypeVar("F", bound=NttField)
X = TypeVar("X", bound=Xof)

PreambleMeasurement: TypeAlias = list[
    # Each element is a pair of block index, and the respective
    # block content (a list of integers).
    tuple[tuple[bool, ...], list[int]]
]

PreamblePrepMessage: TypeAlias = tuple[bytes, bytes]
PreambleOutputShare: TypeAlias = list[F]
PreambleAggShare: TypeAlias = list[F]
PreambleAggResult: TypeAlias = list[int]


class PreamblePublicShare:
    def __init__(self,
                 obs_public_shares: list[OneBlockSparsePublicShare],
                 wr_joint_rand_parts: list[bytes],
                 vf_joint_rand_parts: list[bytes]):
        """
        :param obs_public_shares: one public share for each one-block sparse
                                  DPF.
        """
        self.obs_public_shares = obs_public_shares
        self.wr_joint_rand_parts = wr_joint_rand_parts
        self.vf_joint_rand_parts = vf_joint_rand_parts

    @classmethod
    def from_bytes(cls, bytes: bytes):
        raise NotImplementedError

    @staticmethod
    def encode_obs_public_shares(
        obs_public_shares: list[OneBlockSparsePublicShare],
        field) -> bytes:
        result = bytes()
        for public_share in obs_public_shares:
            for internal_cw in public_share.internal_cw_list:
                result += internal_cw.seed_cw
                result += byte(int(internal_cw.ctrl_left_cw))
                result += byte(int(internal_cw.ctrl_right_cw))
            result += field.encode_vec(public_share.leaf_cw)
            result += public_share.proof_cw
        return result


class PreambleInputShare:
    def __init__(self,
                 obs_seeds: list[bytes],
                 meas_share: Union[list[F], bytes],
                 proofs_share: Union[list[F], bytes],
                 wr_joint_rand_blind: bytes,
                 vf_joint_rand_blind: bytes):
        """
        :param obs_seeds: a list of seeds, one for each one-block sparse DPF.
        :param meas_share: measurement share for PINE proof.
        :param proofs_share: proof share for PINE proof.
        :param wr_joint_rand_blind: wraparound joint randomness seed blind.
        :param vf_joint_rand_blind: verification joint randomness seed blind.
        """
        self.obs_seeds = obs_seeds
        self.meas_share = meas_share
        self.proofs_share = proofs_share
        self.wr_joint_rand_blind = wr_joint_rand_blind
        self.vf_joint_rand_blind = vf_joint_rand_blind


class PreamblePrepState:
    def __init__(self,
                 output_share: list[F],
                 corrected_wr_joint_rand_seed: bytes,
                 corrected_vf_joint_rand_seed: bytes):
        """
        :param output_share: output share, i.e., secret share of the original
                             client vector.
        :param corrected_wr_joint_rand_seed: corrected wraparound joint
                                             randomness seed computed by the
                                             current aggregator.
        :param corrected_vf_joint_rand_seed: corrected verification joint
                                             randomness seed computed by the
                                             current aggregator.
        """
        self.output_share = output_share
        self.corrected_wr_joint_rand_seed = corrected_wr_joint_rand_seed
        self.corrected_vf_joint_rand_seed = corrected_vf_joint_rand_seed


class PreamblePrepShare:
    def __init__(self,
                 one_hot_check: bytes,
                 verifiers_share: list[F],
                 wr_joint_rand_part: bytes,
                 vf_joint_rand_part: bytes):
        """
        :param one_hot_check: one-hot check by hashing all the proof bytes
                              at the leaf nodes.
        :param verifiers_share: verifiers share computed by the current
                                aggregator.
        :param wr_joint_rand_part: wraparound joint randomness part computed
                                   by the current aggregator.
        :param vf_joint_rand_part: verification joint randomness part computed
                                   by the current aggregator.
        """
        self.one_hot_check = one_hot_check
        self.verifiers_share = verifiers_share
        self.wr_joint_rand_part = wr_joint_rand_part
        self.vf_joint_rand_part = vf_joint_rand_part


class Preamble(
        Generic[F, X],
        Vdaf[
            PreambleMeasurement,
            None,  # Preamble doesn't use aggregation param.
            PreamblePublicShare,
            PreambleInputShare,
            PreambleOutputShare,
            PreambleAggShare,
            PreambleAggResult,
            PreamblePrepState,
            PreamblePrepShare,
            PreamblePrepMessage,
        ]):

    # Required properties by `Vdaf`:
    ID: int = 0xFFFF1008 # preambleProofField32HmacSha256Aes128
    NONCE_SIZE = 16
    SHARES = 2
    ROUNDS = 1
    test_vec_name = 'Preamble'
    RAND_SIZE: int  # to be set by constructor
    VERIFY_KEY_SIZE: int  # to be set by constructor

    # Other parameters set by constructor.
    field: type[F]
    xof: type[X]
    obs: PreambleOneBlockSparse
    dimension: int
    num_kept_blocks: int
    # The following properties are all needed to run PINE proof.
    chunk_length: int
    chunk_length_norm_equality: int
    pine_valid: PineValid[F]
    pine_flp_norm_equality: FlpBBCGGI19[list[float], list[float], F]
    pine_flp: FlpBBCGGI19[list[float], list[float], F]
    PROOFS: int
    PROOFS_NORM_EQUALITY: int

    def __init__(self,
                 field: type[F],
                 dimension: int,
                 block_size: int,
                 num_kept_blocks: int,
                 l2_norm_bound: int,
                 chunk_length: int,
                 chunk_length_norm_equality: int,
                 num_proofs: int = 1,
                 num_proofs_norm_equality: int = 1,
                 xof: type[X] = XofHmacSha256Aes128):
        """
        :param field: field size.
        :param dimension: dimension of the original vector space.
        :param block_size: block size used to divide the vector.
        :param num_kept_blocks: number of blocks that are non-zero.
        :param l2_norm_bound: L2-norm bound of all the non-zero blocks combined.
        :param chunk_length: chunk length used in PINE FLP checks, other than
                             norm equality check.
        :param chunk_length_norm_equality: chunk length used in PINE FLP norm
                                           equality check.
        :param num_proofs: number of proofs for PINE FLP checks, other than
                           norm equality check.
        :param num_proofs_norm_equality: number of proofs for PINE FLP norm
                                         equality check.
        :param xof: XOF type.
        """
        if dimension < 1:
            raise ValueError("Dimension must be positive.")
        if block_size < 1:
            raise ValueError("Block size must be positive.")
        if num_kept_blocks < 1 or num_kept_blocks > dimension // block_size:
            raise ValueError(
                "num_kept_blocks must be in [1, dimension // block_size].")
        self.field = field
        self.xof = xof
        self.dimension = dimension
        # Each super block is padded up so that its size is the smallest
        # multiple of `block_size` for which `padded_super_block_size /
        # block_size` is a power of 2 and `padded_super_block_size *
        # num_kept_blocks >= dimension`. The user vector occupies a
        # contiguous prefix `[0, dimension)` of the buffer; positions
        # `[dimension, padded_super_block_size * num_kept_blocks)` are
        # trailing padding within the last super block.
        num_leaf_nodes = (
            (dimension + num_kept_blocks * block_size - 1)
            // (num_kept_blocks * block_size))
        if num_leaf_nodes > 1:
            num_leaf_nodes = 1 << (num_leaf_nodes - 1).bit_length()
        padded_super_block_size = num_leaf_nodes * block_size
        # `num_kept_blocks` must exactly cover the dimension. Otherwise the
        # trailing super blocks would be pure padding (no in-dimension
        # positions), which is a degenerate configuration.
        num_active_super_blocks = (
            (dimension + padded_super_block_size - 1)
            // padded_super_block_size)
        if num_kept_blocks != num_active_super_blocks:
            raise ValueError(
                f"num_kept_blocks={num_kept_blocks} must equal "
                f"num_active_super_blocks={num_active_super_blocks} "
                f"(dimension={dimension}, block_size={block_size}). The "
                f"last {num_kept_blocks - num_active_super_blocks} super "
                f"block(s) have no in-dimension positions; pick "
                f"num_kept_blocks={num_active_super_blocks}.")
        self.padded_super_block_size = padded_super_block_size
        self.obs = PreambleOneBlockSparse(
            field=field,
            super_block_size=padded_super_block_size,
            block_size=block_size,
            nonce_size=self.NONCE_SIZE,
            xof=xof,
            algorithm_id=self.ID)
        self.num_kept_blocks = num_kept_blocks
        self.l2_norm_bound = l2_norm_bound
        pine_dimension = num_kept_blocks * block_size
        self.chunk_length = chunk_length
        self.chunk_length_norm_equality = chunk_length_norm_equality
        (pine_valid_norm_equality, self.pine_valid) = construct_circuits(
            field=field,
            l2_norm_bound=l2_norm_bound,
            # We assert the norm bound with `l2_norm_bound` directly.
            num_frac_bits=0,
            dimension=pine_dimension,
            chunk_length=chunk_length,
            chunk_length_norm_equality=chunk_length_norm_equality,
            alpha=ALPHA,
            num_wr_checks=NUM_WR_CHECKS,
            num_wr_successes=NUM_WR_SUCCESSES
        )
        self.pine_flp_norm_equality = FlpBBCGGI19(pine_valid_norm_equality)
        self.pine_flp = FlpBBCGGI19(self.pine_valid)
        self.PROOFS = num_proofs
        self.PROOFS_NORM_EQUALITY = num_proofs_norm_equality
        self.VERIFY_KEY_SIZE = self.xof.SEED_SIZE
        # The size of randomness is the sum of the randomness size needed by
        # `PreambleOneBlockSparse` times `num_kept_blocks` +
        # the seed size times the sum of the following:
        # - Helper's measurement share seed.
        # - Helper's proof share seed.
        # - Two joint randomness seed blind for each Aggregator, one for
        #   wraparound check, one for verification.
        # - One prover randomness seed.
        self.RAND_SIZE = (self.obs.RAND_SIZE * num_kept_blocks +
            (1 + 1 + 2 * 2 + 1) * self.xof.SEED_SIZE)

    def shard(self,
              measurement: PreambleMeasurement,
              nonce: bytes,
              rand: bytes,
              ) -> tuple[PreamblePublicShare, list[PreambleInputShare]]:
        if len(measurement) != self.num_kept_blocks:
            raise ValueError(
                f"Measurement can select at most {self.num_kept_blocks} blocks.")

        leader_id = 0
        helper_id = 1

        leader_obs_seeds = []
        for _ in range(self.num_kept_blocks):
            (seed, rand) = front(self.xof.SEED_SIZE, rand)
            leader_obs_seeds.append(seed)
        helper_obs_seeds = []
        for _ in range(self.num_kept_blocks):
            (seed, rand) = front(self.xof.SEED_SIZE, rand)
            helper_obs_seeds.append(seed)
        # Helper's seeds:
        # Helper's measurement share for PINE proof.
        (helper_meas_share, rand) = front(self.xof.SEED_SIZE, rand)
        # Helper's proofs share.
        (helper_proofs_share, rand) = front(self.xof.SEED_SIZE, rand)
        # Helper's seed blind to generate the wraparound joint randomness.
        (helper_wr_joint_rand_blind, rand) = front(self.xof.SEED_SIZE, rand)
        # Helper's seed blind to generate the verification joint randomness.
        (helper_vf_joint_rand_blind, rand) = front(self.xof.SEED_SIZE, rand)

        # Leader's seeds:
        # Leader's seed blind to generate the wraparound joint randomness.
        (leader_wr_joint_rand_blind, rand) = front(self.xof.SEED_SIZE, rand)
        # Leader's seed blind to generate the verification joint randomness.
        (leader_vf_joint_rand_blind, rand) = front(self.xof.SEED_SIZE, rand)

        # Prover randomness:
        (prove_rand_seed, rand) = front(self.xof.SEED_SIZE, rand)

        obs_public_shares = []
        encoded_blocks = []
        for i, (block_index, block_content) in enumerate(measurement):
            encoded_block = self.obs.encode_into_field_elements(
                block_content)
            encoded_blocks.extend(encoded_block)
            obs_rand = leader_obs_seeds[i] + helper_obs_seeds[i]
            leaf_index = 0
            for b in block_index:
                leaf_index = (leaf_index << 1) | int(b)
            (obs_public_share, seeds) = self.obs.gen(
                leaf_index, encoded_block, nonce, obs_rand)
            obs_public_shares.append(obs_public_share)
            leader_obs_seeds[i] = seeds[leader_id]
            helper_obs_seeds[i] = seeds[helper_id]
        assert len(rand) == 0

        encoded_obs_public_shares = \
            PreamblePublicShare.encode_obs_public_shares(
                obs_public_shares, self.field)

        # Run norm check (before WR JR so norm shares can be included
        # in binder).
        encoded_norm = self.pine_valid.encode_norm(encoded_blocks)

        # Expand helper's full measurement share once (covers norm +
        # wr_check_bits).
        norm_len = 2 * self.pine_valid.num_bits_for_sq_norm
        helper_meas_share_expanded = self.helper_meas_share(
            helper_meas_share, self.pine_valid.bit_checked_len)
        helper_norm_share = helper_meas_share_expanded[:norm_len]
        leader_norm_share = vec_sub(encoded_norm, helper_norm_share)

        # Derive the wraparound joint randomness xof for PINE.
        # WR JR now includes norm share in binder.
        leader_wr_joint_rand_part = self.wr_joint_rand_part(
            0, leader_wr_joint_rand_blind, nonce, encoded_obs_public_shares,
            leader_obs_seeds, leader_norm_share)
        helper_wr_joint_rand_part = self.wr_joint_rand_part(
            1, helper_wr_joint_rand_blind, nonce, encoded_obs_public_shares,
            helper_obs_seeds, helper_norm_share)
        wr_joint_rand_seed = self.joint_rand_seed(
            [leader_wr_joint_rand_part, helper_wr_joint_rand_part],
            USAGE_WR_JOINT_RAND_SEED
        )
        wr_joint_rand_xof = self.wr_joint_rand_xof(wr_joint_rand_seed)

        # Run wraparound check.
        (wr_check_bits, wr_check_results) = self.pine_valid.encode_wr_checks(
            encoded_blocks, wr_joint_rand_xof)
        # This is the measurement to be secret-shared, and sent as part of the
        # input share to the two aggregators, in order to compute the PINE
        # proof. The original encoded blocks are already in the leaf correction
        # word, so we don't secret-share them again in input shares.
        pine_meas = encoded_norm + wr_check_bits
        assert len(pine_meas) == self.pine_valid.bit_checked_len

        # Derive the verification JR. Reuse the already-expanded
        # helper share to avoid re-expanding.
        helper_wr_bits_share = helper_meas_share_expanded[norm_len:]
        leader_wr_bits_share = vec_sub(wr_check_bits, helper_wr_bits_share)
        leader_meas_share = leader_norm_share + leader_wr_bits_share
        leader_vf_joint_rand_part = self.vf_joint_rand_part(
            leader_id,
            leader_vf_joint_rand_blind,
            nonce,
            encoded_obs_public_shares,
            leader_obs_seeds,
            leader_meas_share
        )
        helper_vf_joint_rand_part = self.vf_joint_rand_part(
            helper_id,
            helper_vf_joint_rand_blind,
            nonce,
            encoded_obs_public_shares,
            helper_obs_seeds,
            helper_meas_share_expanded
        )
        # Compute verification joint randomness field elements.
        vf_joint_rand_seed = self.joint_rand_seed(
            [leader_vf_joint_rand_part, helper_vf_joint_rand_part],
            USAGE_JOINT_RAND_SEED,
        )
        vf_joint_rands = self.vf_joint_rands(vf_joint_rand_seed)

        # Generate the proof and shard it into proof shares.
        pine_full_meas = encoded_blocks + pine_meas + wr_check_results
        prove_rands = self.xof.expand_into_vec(
            self.field,
            prove_rand_seed,
            dst_alg(USAGE_PROVE_RANDOMNESS, self.ID),
            byte(self.PROOFS_NORM_EQUALITY) + byte(self.PROOFS),
            self.pine_flp_norm_equality.PROVE_RAND_LEN * self.PROOFS_NORM_EQUALITY +
            self.pine_flp.PROVE_RAND_LEN * self.PROOFS
        )
        leader_proofs_share = []

        # Proofs for norm equality check.
        for _ in range(self.PROOFS_NORM_EQUALITY):
            (prove_rand, prove_rands) = \
                front(self.pine_flp_norm_equality.PROVE_RAND_LEN, prove_rands)
            leader_proofs_share += self.pine_flp_norm_equality.prove(
                pine_full_meas, prove_rand, [])
        # Proofs for all other checks.
        for _ in range(self.PROOFS):
            (prove_rand, prove_rands) = \
                front(self.pine_flp.PROVE_RAND_LEN, prove_rands)
            (vf_joint_rand, vf_joint_rands) = \
                front(self.pine_flp.JOINT_RAND_LEN, vf_joint_rands)
            leader_proofs_share += self.pine_flp.prove(pine_full_meas,
                                                       prove_rand,
                                                       vf_joint_rand)
        # Sanity check:
        assert len(prove_rands) == 0
        assert len(vf_joint_rands) == 0

        # Secret-share proofs share to compute leader's proofs share.
        leader_proofs_share = vec_sub(
            leader_proofs_share, self.helper_proofs_share(helper_proofs_share)
        )

        return (
            PreamblePublicShare(
                obs_public_shares=obs_public_shares,
                wr_joint_rand_parts=[leader_wr_joint_rand_part,
                                     helper_wr_joint_rand_part],
                vf_joint_rand_parts=[leader_vf_joint_rand_part,
                                     helper_vf_joint_rand_part]
            ),
            [
                PreambleInputShare(
                    obs_seeds=leader_obs_seeds,
                    meas_share=leader_meas_share,
                    proofs_share=leader_proofs_share,
                    wr_joint_rand_blind=leader_wr_joint_rand_blind,
                    vf_joint_rand_blind=leader_vf_joint_rand_blind
                ),
                PreambleInputShare(
                    obs_seeds=helper_obs_seeds,
                    meas_share=helper_meas_share,
                    proofs_share=helper_proofs_share,
                    wr_joint_rand_blind=helper_wr_joint_rand_blind,
                    vf_joint_rand_blind=helper_vf_joint_rand_blind
                )
            ]
        )

    def is_valid(self, _agg_param, previous_agg_params):
        """
        Checks if `previous_agg_params` is empty, as input shares in Preamble
        may only be used once.
        """
        return len(previous_agg_params) == 0

    def prep_init(
            self,
            verify_key: bytes,
            agg_id: int,
            agg_param: None,
            nonce: bytes,
            public_share: PreamblePublicShare,
            input_share: PreambleInputShare,
    ) -> tuple[PreamblePrepState, PreamblePrepShare]:
        initial_ctrl_bit = agg_id > 0  # Same used by the client.
        output_share = []
        one_hot_check_binder = bytes()
        # This is the secret share of the blocks set by the client.
        # We obtain the secret share on aggregator, by summing the blocks
        # coordinate-wise for each super block, and concatenate the sum.
        encoded_blocks_share: list[F] = []
        for sb_idx in range(self.num_kept_blocks):
            obs_public_share = public_share.obs_public_shares[sb_idx]
            initial_seed = input_share.obs_seeds[sb_idx]
            summed_blocks = self.field.zeros(self.obs.block_size)
            super_block_start = sb_idx * self.padded_super_block_size
            # The last super block may not have all the blocks within
            # `dimension`.
            output_count = min(
                self.padded_super_block_size,
                self.dimension - super_block_start)
            (super_block_output_share, proofs) = self.obs.eval_all(
                nonce,
                agg_id,
                initial_seed,
                initial_ctrl_bit,
                obs_public_share,
                output_count,
            )
            output_share.extend(super_block_output_share)
            one_hot_check_binder += concat(proofs)
            for i in range(len(super_block_output_share)):
                summed_blocks[i % self.obs.block_size] += \
                    super_block_output_share[i]
            encoded_blocks_share.extend(summed_blocks)
        assert len(output_share) == self.dimension
        assert len(encoded_blocks_share) == \
            self.obs.block_size * self.num_kept_blocks

        # Hash all proof bytes at the leaf nodes to check one-hotness.
        one_hot_check = self.xof(
            verify_key,
            dst_alg(USAGE_ONEHOT_CHECK, self.ID),
            one_hot_check_binder,
        ).next(PROOF_SIZE)

        encoded_obs_public_shares = \
            PreamblePublicShare.encode_obs_public_shares(
                public_share.obs_public_shares, self.field)

        (meas_share, proofs_share) = (
            (input_share.meas_share, input_share.proofs_share) if agg_id == 0
            else (self.helper_meas_share(input_share.meas_share,
                                         self.pine_valid.bit_checked_len),
                  self.helper_proofs_share(input_share.proofs_share))
        )

        # Derive the wraparound joint randomness xof for PINE.
        # Include norm share prefix in wraparound JR binder.
        norm_len = 2 * self.pine_valid.num_bits_for_sq_norm
        wr_joint_rand_part = self.wr_joint_rand_part(
            agg_id, input_share.wr_joint_rand_blind, nonce,
            encoded_obs_public_shares, input_share.obs_seeds,
            meas_share[:norm_len])
        public_share.wr_joint_rand_parts[agg_id] = wr_joint_rand_part
        corrected_wr_joint_rand_seed = self.joint_rand_seed(
            public_share.wr_joint_rand_parts,
            USAGE_WR_JOINT_RAND_SEED
        )
        wr_joint_rand_xof = self.wr_joint_rand_xof(corrected_wr_joint_rand_seed)
        # With the wraparound joint randomness xof, and the secret share of
        # the encoded blocks, compute the wraparound check results.
        wr_check_results = self.pine_valid.run_wr_checks(
            encoded_blocks_share, wr_joint_rand_xof
        )

        vf_joint_rand_part = self.vf_joint_rand_part(
            agg_id,
            input_share.vf_joint_rand_blind,
            nonce,
            encoded_obs_public_shares,
            input_share.obs_seeds,
            meas_share
        )
        public_share.vf_joint_rand_parts[agg_id] = vf_joint_rand_part
        corrected_vf_joint_rand_seed = self.joint_rand_seed(
            public_share.vf_joint_rand_parts,
            USAGE_JOINT_RAND_SEED
        )
        vf_joint_rands = self.vf_joint_rands(corrected_vf_joint_rand_seed)

        # Query the measurement and proof share.
        # `PineValid.eval()` expects the wraparound check results (i.e., the dot
        # products) to be appended at the end of Client's encoded measurement.
        pine_meas_share = encoded_blocks_share + meas_share + wr_check_results
        query_rands = self.xof.expand_into_vec(
            self.field,
            verify_key,
            dst_alg(USAGE_QUERY_RANDOMNESS, self.ID),
            byte(self.PROOFS_NORM_EQUALITY) + byte(self.PROOFS) + nonce,
            self.pine_flp_norm_equality.QUERY_RAND_LEN * self.PROOFS_NORM_EQUALITY +
            self.pine_flp.QUERY_RAND_LEN * self.PROOFS
        )
        verifiers_share = []
        # Query the proofs for norm equality check.
        for _ in range(self.PROOFS_NORM_EQUALITY):
            (proof_share, proofs_share) = front(
                self.pine_flp_norm_equality.PROOF_LEN, proofs_share)
            (query_rand, query_rands) = \
                front(self.pine_flp_norm_equality.QUERY_RAND_LEN, query_rands)
            verifiers_share += self.pine_flp_norm_equality.query(
                pine_meas_share,
                proof_share,
                query_rand,
                [],
                self.SHARES
            )

        # Query the proofs for all other checks.
        for _ in range(self.PROOFS):
            (proof_share, proofs_share) = front(
                self.pine_flp.PROOF_LEN, proofs_share)
            (vf_joint_rand, vf_joint_rands) = \
                front(self.pine_flp.JOINT_RAND_LEN, vf_joint_rands)
            (query_rand, query_rands) = \
                front(self.pine_flp.QUERY_RAND_LEN, query_rands)
            verifiers_share += self.pine_flp.query(pine_meas_share,
                                                   proof_share,
                                                   query_rand,
                                                   vf_joint_rand,
                                                   self.SHARES)
        # Sanity check:
        assert len(proofs_share) == 0
        assert len(vf_joint_rands) == 0
        assert len(query_rands) == 0

        return (
            PreamblePrepState(
                output_share,
                corrected_wr_joint_rand_seed,
                corrected_vf_joint_rand_seed
            ),
            PreamblePrepShare(
                one_hot_check,
                verifiers_share,
                wr_joint_rand_part,
                vf_joint_rand_part
            )
        )

    def prep_shares_to_prep(self,
                            _agg_param: None,
                            prep_shares: list[PreamblePrepShare],
                            ) -> PreamblePrepMessage:
        assert len(prep_shares) == self.SHARES
        if prep_shares[0].one_hot_check != prep_shares[1].one_hot_check:
            raise ValueError("One-hot check failed")

        # Unshard the verifier shares into the verifier message.
        verifiers = [x + y for (x, y) in zip(prep_shares[0].verifiers_share,
                                             prep_shares[1].verifiers_share)]
        wr_joint_rand_parts = [prep_shares[0].wr_joint_rand_part,
                               prep_shares[1].wr_joint_rand_part]
        vf_joint_rand_parts = [prep_shares[0].vf_joint_rand_part,
                               prep_shares[1].vf_joint_rand_part]

        # Verify that each proof is well-formed and input is valid.
        for _ in range(self.PROOFS_NORM_EQUALITY):
            (verifier, verifiers) = front(
                self.pine_flp_norm_equality.VERIFIER_LEN, verifiers)
            if not self.pine_flp_norm_equality.decide(verifier):
                # Proof verifier check failed.
                raise ValueError("Decision function for norm equality check "
                                 "failed after combining all verifier shares.")

        for _ in range(self.PROOFS):
            (verifier, verifiers) = front(self.pine_flp.VERIFIER_LEN, verifiers)
            if not self.pine_flp.decide(verifier):
                # Proof verifier check failed.
                raise ValueError("Decision function for other checks failed "
                                 "after combining all verifier shares.")

        # Sanity check:
        assert len(verifiers) == 0

        # Combine the joint randomness parts computed by the Aggregators
        # into the true joint randomness seeds, which are checked by all
        # Aggregators.
        return (
            self.joint_rand_seed(wr_joint_rand_parts, USAGE_WR_JOINT_RAND_SEED),
            self.joint_rand_seed(vf_joint_rand_parts, USAGE_JOINT_RAND_SEED)
        )

    def prep_next(self,
                  prep_state: PreamblePrepState,
                  prep_msg: PreamblePrepMessage,
                  ) -> PreambleOutputShare:
        # Joint randomness seeds sent by the other aggregator.
        (wr_joint_rand_seed, vf_joint_rand_seed) = prep_msg

        # Make sure the seeds from the other aggregator are consistent with
        # ones computed by the current aggregator.
        if (wr_joint_rand_seed != prep_state.corrected_wr_joint_rand_seed or
                vf_joint_rand_seed != prep_state.corrected_vf_joint_rand_seed):
            raise ValueError("Inconsistency between the seeds.")
        return prep_state.output_share

    def aggregate(self,
                  _agg_param: None,
                  out_shares: list[PreambleOutputShare]) -> PreambleAggShare:
        agg_share = self.field.zeros(self.dimension)
        for out_share in out_shares:
            agg_share = vec_add(agg_share, out_share)
        return agg_share

    def unshard(self,
                _agg_param: None,
                agg_shares: list[PreambleAggShare],
                num_measurements: int) -> PreambleAggResult:
        agg = self.field.zeros(self.dimension)
        for agg_share in agg_shares:
            agg = vec_add(agg, agg_share)
        return self.obs.decode_from_field_elements(agg)

    # Helper methods:

    def wr_joint_rand_part(self,
                           agg_id: int,
                           seed_blind: bytes,
                           nonce: bytes,
                           encoded_public_share: bytes,
                           obs_seeds: list[bytes],
                           expanded_norm_share: list[F]) -> bytes:
        return self.xof.derive_seed(
            seed_blind,
            dst_alg(USAGE_WR_JOINT_RAND_PART, self.ID),
            byte(agg_id) + nonce + encoded_public_share + concat(obs_seeds)
            + self.field.encode_vec(expanded_norm_share)
        )

    def wr_joint_rand_xof(self, seed: bytes) -> X:
        """Initialize the XOF to sample wraparound joint randomness. """
        return self.xof(
            seed,
            dst_alg(USAGE_WR_JOINT_RANDOMNESS, self.ID),
            b'',
        )

    def vf_joint_rand_part(self,
                           agg_id: int,
                           seed_blind: bytes,
                           nonce: bytes,
                           encoded_public_share: bytes,
                           obs_seeds: list[bytes],
                           expanded_meas_share: list[F]) -> bytes:
        return self.xof.derive_seed(
            seed_blind,
            dst_alg(USAGE_JOINT_RAND_PART, self.ID),
            (byte(agg_id) + nonce + encoded_public_share + concat(obs_seeds) +
                self.field.encode_vec(expanded_meas_share)),
        )

    def vf_joint_rands(self, seed: bytes) -> list[F]:
        """
        Derive the verification joint randomness based on the initial seed.
        """
        return self.xof.expand_into_vec(
            self.field,
            seed,
            dst_alg(USAGE_JOINT_RANDOMNESS, self.ID),
            byte(self.PROOFS),
            self.pine_flp.JOINT_RAND_LEN * self.PROOFS
        )

    def joint_rand_seed(self,
                        joint_rand_parts: list[bytes],
                        usage: int) -> bytes:
        """
        Derive the joint randomness seed from its parts and based on the usage.
        """
        return self.xof.derive_seed(
            zeros(self.xof.SEED_SIZE),
            dst_alg(usage, self.ID),
            concat(joint_rand_parts),
        )

    def helper_meas_share(self,
                          helper_meas_share: bytes,
                          meas_len: int) -> list[F]:
        """
        Expand helper's seed for measurement share into a list of field elements.
        """
        return self.xof.expand_into_vec(
            self.field,
            helper_meas_share,
            dst_alg(USAGE_MEAS_SHARE, self.ID),
            byte(1),
            meas_len
        )

    def helper_proofs_share(self, proofs_share: bytes) -> list[F]:
        """
        Expand helper's seed for proofs share into a list of field elements.
        """
        return self.xof.expand_into_vec(
            self.field,
            proofs_share,
            dst_alg(USAGE_PROOF_SHARE, self.ID),
            byte(self.PROOFS_NORM_EQUALITY) + byte(self.PROOFS) + byte(1),
            self.pine_flp_norm_equality.PROOF_LEN * self.PROOFS_NORM_EQUALITY +
            self.pine_flp.PROOF_LEN * self.PROOFS
        )

    # Methods to generate test vectors:

    def test_vec_set_type_param(self, test_vec: dict[str, Any]) -> list[str]:
        test_vec["dimension"] = self.dimension
        test_vec["block_size"] = self.obs.block_size
        test_vec["num_kept_blocks"] = self.num_kept_blocks
        test_vec["l2_norm_bound"] = self.l2_norm_bound
        test_vec["chunk_length"] = self.chunk_length
        test_vec["chunk_length_norm_equality"] = self.chunk_length_norm_equality
        return ["dimension", "block_size", "num_kept_blocks", "l2_norm_bound", "chunk_length", "chunk_length_norm_equality"]

    def test_vec_encode_input_share(self, input_share: PreambleInputShare) -> bytes:
        encoded = bytes()
        # Encode the observation seeds
        encoded += concat(input_share.obs_seeds)

        # Encode measurement share
        if isinstance(input_share.meas_share, list):  # Leader
            encoded += self.field.encode_vec(input_share.meas_share)
        else:  # Helper (seed)
            encoded += input_share.meas_share

        # Encode proofs share
        if isinstance(input_share.proofs_share, list):  # Leader
            encoded += self.field.encode_vec(input_share.proofs_share)
        else:  # Helper (seed)
            encoded += input_share.proofs_share

        # Encode joint randomness blinds
        encoded += input_share.wr_joint_rand_blind
        encoded += input_share.vf_joint_rand_blind

        return encoded

    def test_vec_encode_public_share(self, public_share: PreamblePublicShare) -> bytes:
        encoded = bytes()
        # Encode the observation public shares
        encoded += PreamblePublicShare.encode_obs_public_shares(
            public_share.obs_public_shares, self.field)
        # Encode wraparound joint randomness parts
        encoded += concat(public_share.wr_joint_rand_parts)
        # Encode verification joint randomness parts
        encoded += concat(public_share.vf_joint_rand_parts)
        return encoded

    def test_vec_encode_agg_share(self, agg_share: PreambleAggShare) -> bytes:
        return self.field.encode_vec(agg_share)

    def test_vec_encode_prep_share(self, prep_share: PreamblePrepShare) -> bytes:
        encoded = bytes()
        # Encode one-hot check
        encoded += prep_share.one_hot_check
        # Encode verifiers share
        encoded += self.field.encode_vec(prep_share.verifiers_share)
        # Encode wraparound joint randomness part
        encoded += prep_share.wr_joint_rand_part
        # Encode verification joint randomness part
        encoded += prep_share.vf_joint_rand_part
        return encoded

    def test_vec_encode_prep_msg(self, prep_message: PreamblePrepMessage) -> bytes:
        # Prep message is a tuple of (wr_joint_rand_seed, vf_joint_rand_seed)
        (wr_joint_rand_seed, vf_joint_rand_seed) = prep_message
        return wr_joint_rand_seed + vf_joint_rand_seed

"""Preamble's DPF implementation. """

from typing import Generic, TypeAlias, TypeVar

from vdaf_poc.common import vec_add, vec_neg, vec_sub, xor
from vdaf_poc.field import NttField
from vdaf_poc.xof import Xof

from dst import USAGE_CONVERT, USAGE_EXTEND, dst_alg

F = TypeVar("F", bound=NttField)

PROOF_SIZE = 32

LeafCorrectionWord: TypeAlias = list[F]
ProofCorrectionWord: TypeAlias = bytes


class InternalCorrectionWord:
    def __init__(self, seed_cw: bytes, ctrl_left_cw: bool, ctrl_right_cw: bool):
        self.seed_cw = seed_cw
        self.ctrl_left_cw = ctrl_left_cw
        self.ctrl_right_cw = ctrl_right_cw


class OneBlockSparsePublicShare:
    def __init__(self,
                 internal_cw_list: list[InternalCorrectionWord],
                 leaf_cw: LeafCorrectionWord,
                 proof_cw: ProofCorrectionWord):
        self.internal_cw_list = internal_cw_list
        self.leaf_cw = leaf_cw
        self.proof_cw = proof_cw


class EvalNode:
    """
    A small class that represents a node during evaluation.
    """

    def __init__(self, level: int, seed: bytes, ctrl_bit: bool, leaf_index: int = 0):
        self.level = level
        self.seed = seed
        self.ctrl_bit = ctrl_bit
        self.leaf_index = leaf_index



class PreambleOneBlockSparse(Generic[F]):
    """
    A vector (or a segment/"super block" of a vector) with `super_block_size`
    elements, divided into blocks of `block_size` elements, and only one block
    is set to non-zero, and other blocks are all 0.

    We note that the internal node's gen and eval algorithms are very similar to
    Mastic's:
    https://github.com/jimouris/draft-mouris-cfrg-mastic/blob/main/poc/vidpf.py,
    as described in Fig. 15 and Fig. 16 of https://eprint.iacr.org/2023/080.pdf
    Except we make the following changes in Preamble:
    - Preamble doesn't use beta at every internal node, since our goal is to
      only expand the field elements at the leaf nodes.
    - The beta in Preamble's leaf node is a block of field elements.
    """
    def __init__(self, field: type[F], super_block_size: int,
                 block_size: int, nonce_size: int, xof: Xof,
                 algorithm_id: int):
        if super_block_size & (super_block_size - 1) != 0:
            raise ValueError("Dimension must be power of 2.")
        if block_size & (block_size - 1) != 0:
            raise ValueError("Block size must be power of 2.")
        self.xof = xof
        self.algorithm_id = algorithm_id
        self.KEY_SIZE = self.xof.SEED_SIZE
        self.NONCE_SIZE = nonce_size
        self.RAND_SIZE = 2 * xof.SEED_SIZE
        self.field = field
        self.super_block_size = super_block_size
        self.block_size = block_size
        self.num_leaf_nodes = int(super_block_size / block_size)
        # `self.depth` takes into the account of the number of levels from root
        # node to the leaf node that expands to the block of field elements.
        # Example (`x` signals the internal tree node, `y` signals an actual
        # coordinate in the actual vector):
        # super_block_size = 2, block_size = 1, depth = 2:
        #    x
        #  /   \
        # x     x
        # super_block_size = 4, block_size = 2, depth = 2:
        #        x
        #     /     \
        #    x       x
        #  /   \   /   \
        # y    y  y     y
        # super_block_size = 8, block_size = 4, depth = 2:
        #               x
        #           /        \
        #          x           x
        #       / | | \     / | | \
        #      y  y y  y   y  y y  y
        self.depth = (int(self.num_leaf_nodes)).bit_length()

    def gen(self,
            leaf_index: int,  # Block index as an integer.
            values: list[F],  # All the values for the block.
            nonce: bytes,
            rand: bytes,
            ) -> tuple[OneBlockSparsePublicShare, list[bytes]]:
        '''
        Preamble generation algorithm.
        We note most of the generation logic is very similar to standard DPF
        construction, so we reuse most of the Mastic construction:
        https://github.com/jimouris/draft-mouris-cfrg-mastic/blob/main/poc/vidpf.py
        as described in Fig. 15 in paper: https://eprint.iacr.org/2023/080.pdf

        Returns the public share (i.e., the correction word for each internal
        level and leaf level of the tree), and two initial seeds, one for each
        aggregator, and proof correction word.
        '''
        if leaf_index >= self.num_leaf_nodes:
            raise ValueError("leaf_index out of range")
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError("incorrect nonce size")
        if len(rand) != self.RAND_SIZE:
            raise ValueError("randomness has incorrect length")

        # Step 1: Initial seeds sent to leader and helper.
        initial_seeds = [rand[:self.KEY_SIZE], rand[self.KEY_SIZE:]]
        # Seeds that are updated in each level of the tree.
        seeds = initial_seeds.copy()
        # Step 2: Signal for each aggregator whether to apply correction words.
        # We maintain the invariant such that:
        # - If a node is on path, ctrl[0] ^ ctrl[1] = 1.
        # - If a node is off path, ctrl[0] ^ ctrl[1] = 0.
        # Initially set the helper's index to be True, so helper applies the
        # correction word.
        ctrl = [False, True]
        # Compute the internal-level correction words sent to both aggregators.
        internal_cw_list = []
        # Step 3: Loop through each internal level of the DPF tree.
        for i in range(self.depth - 1):
            bit = (leaf_index >> (self.depth - 2 - i)) & 1

            # Step 4: Expand PRG into seed and control bit for both aggregators.
            (s0, t0) = self.extend(seeds[0], nonce)
            (s1, t1) = self.extend(seeds[1], nonce)

            # Steps 5 and 6: If the current level is a 1, we will traverse the
            # right child (`keep` set to 1).
            # Otherwise, traverse the left child (`keep` set to 0).
            (keep, lose) = (1, 0) if bit else (0, 1)

            # Steps 7, 8, 9: Compute the correction words for this level's
            # seed and control bit. Our goal is to maintain the following
            # invariant, after correction:
            #
            # * If evaluation is on path, then each aggregator will
            #   compute a different seed and their control bits will be
            #   secret shares of one.
            #
            # * If evaluation is off path, then the aggregators will
            #   compute the same seed and their control bits will be
            #   shares of zero.
            #
            # Implementation note: the index `lose` is `alpha`-dependent.
            seed_cw = xor(s0[lose], s1[lose])
            ctrl_cw = [
                t0[0] ^ t1[0] ^ (not bit),  # [MST24]: t_c^L
                t0[1] ^ t1[1] ^ bit,        # [MST24]: t_c^R
            ]

            # Steps 10 and 11: Correct.
            #
            # Implementation note: the index `keep` is `alpha`-dependent,
            # as is `ctrl`.
            # If the control bit is set, apply the correction words.
            if ctrl[0]:
                s0[keep] = xor(s0[keep], seed_cw)
                t0[keep] ^= ctrl_cw[keep]
            if ctrl[1]:
                s1[keep] = xor(s1[keep], seed_cw)
                t1[keep] ^= ctrl_cw[keep]

            # After correction, they become next level's seeds and control bits.
            seeds[0] = s0[keep]
            seeds[1] = s1[keep]
            ctrl[0] = t0[keep]
            ctrl[1] = t1[keep]

            internal_cw_list.append(
                InternalCorrectionWord(seed_cw, ctrl_cw[0], ctrl_cw[1]))

        # Similar to step 12: Compute leaf correction.
        # Sample leader and helper's random field elements and also the proofs
        # for block sparsity (3.2 in https://eprint.iacr.org/2025/490.pdf) from
        # their seeds at the leaf level.
        # During generation, we use the full path which is leaf_index (the block index).
        leaf_index_bytes = leaf_index.to_bytes((self.depth - 1 + 7) // 8, byteorder='big')
        (w0, proof0) = self.compute_leaf_level(seeds[0], nonce + leaf_index_bytes)
        (w1, proof1) = self.compute_leaf_level(seeds[1], nonce + leaf_index_bytes)
        # Similar to step 13: Correction word for the block of field elements at
        # leaf level.
        leaf_cw = vec_add(vec_sub(values, w0), w1)

        if ctrl[1]:
            leaf_cw = vec_neg(leaf_cw)
        proof_cw = xor(proof0, proof1)
        return (OneBlockSparsePublicShare(internal_cw_list, leaf_cw, proof_cw),
                initial_seeds)

    def eval_all(self,
                 nonce: bytes,
                 agg_id: int,
                 initial_seed: bytes,
                 initial_ctrl_bit: bool,
                 obs_public_share: OneBlockSparsePublicShare,
                 output_count: int | None = None,
                 ) -> tuple[list[F], list[bytes]]:
        """
        Evaluate the field elements expanded from the leaf nodes.
        We note the evaluation algorithm is very similar to standard DPF
        evaluation, except we will evaluate all the leaf nodes, and expand them
        into secret shares of the original client vector.

        :param output_count: number of field elements to write. Trailing
            leaves whose elements lie entirely beyond `output_count` are
            skipped. The last processed leaf may write fewer than
            `block_size` elements when `output_count % block_size != 0`.
            Defaults to `super_block_size` (i.e., evaluate all leaves).
        """
        if output_count is None:
            output_count = self.super_block_size
        if output_count <= 0 or output_count > self.super_block_size:
            raise ValueError(
                f"output_count={output_count} out of range [1, "
                f"{self.super_block_size}]")
        active_leaf_node_count = (
            output_count + self.block_size - 1) // self.block_size

        root_node = EvalNode(level=0, seed=initial_seed, ctrl_bit=initial_ctrl_bit)
        if self.depth == 1:
            # Nothing to traverse, only need to expand the leaf node.
            internal_nodes = []
            leaf_nodes = [root_node]
        else:
            internal_nodes = [root_node]
            leaf_nodes = []
        # Run BFS on the tree.
        while len(internal_nodes) > 0:
            node = internal_nodes.pop(0)
            (left_child, right_child) = self.eval_next_children(
                nonce, node, obs_public_share.internal_cw_list)
            if node.level < self.depth - 2:
                internal_nodes.append(left_child)
                internal_nodes.append(right_child)
            else:
                leaf_nodes.append(left_child)
                leaf_nodes.append(right_child)

        assert len(leaf_nodes) == self.num_leaf_nodes
        # Process only the first `active_leaf_node_count` leaves.
        # `compute_leaf_level` always samples `block_size` field elements
        # from the XOF before sampling the proof bytes (see `gen`), so the
        # partial last leaf still consumes the full XOF prefix; we only
        # truncate which of the resulting field elements get appended.
        field_elems: list[F] = []
        proofs: list[bytes] = []
        for leaf_idx in range(active_leaf_node_count):
            leaf_node = leaf_nodes[leaf_idx]
            elem_count = (output_count - leaf_idx * self.block_size
                          if leaf_idx == active_leaf_node_count - 1
                          else self.block_size)
            leaf_index_bytes = leaf_node.leaf_index.to_bytes(
                (self.depth - 1 + 7) // 8, byteorder='big')
            (w, proof) = self.compute_leaf_level(
                leaf_node.seed, nonce + leaf_index_bytes)
            if leaf_node.ctrl_bit:
                w = vec_add(w, obs_public_share.leaf_cw)
                proof = xor(proof, obs_public_share.proof_cw)
            if agg_id == 1:
                # Helper negates its share.
                w = vec_neg(w)
            field_elems.extend(w[:elem_count])
            proofs.append(proof)
        return field_elems, proofs

    def encode_into_field_elements(self, vals: list[int]) -> list[F]:
        """
        Encode a list of integers into a field elements.
        A block in Preamble can have negative values, so we allocate upper
        half of the field modulus for negative values.
        """
        return [self.field(val) if val < self.field.MODULUS / 2
                else self.field(self.field.MODULUS + val) for val in vals]

    def decode_from_field_elements(self, field_elems: list[F]) -> list[int]:
        """
        Decode a list of field elements back to integers, the reverse of
        `encode`.
        """
        return [elem.as_unsigned()
                if elem.as_unsigned() < self.field.MODULUS / 2
                else elem.as_unsigned() - self.field.MODULUS
                for elem in field_elems]

    def eval_next_children(self,
                           nonce: bytes,
                           node: EvalNode,
                           internal_cw_list: list[InternalCorrectionWord],
                           ) -> tuple[EvalNode, EvalNode]:
        """
        Evaluate the next and right child of the current `node`.
        The evaluation algorithm is very similar to Mastic's evaluation:
        https://github.com/jimouris/draft-mouris-cfrg-mastic/blob/main/poc/vidpf.py
        as described in Fig. 16 in paper: https://eprint.iacr.org/2023/080.pdf
        """
        # Step 2: Get current level's seed and control bit correction words.
        seed_cw = internal_cw_list[node.level].seed_cw
        ctrl_left_cw = internal_cw_list[node.level].ctrl_left_cw
        ctrl_right_cw = internal_cw_list[node.level].ctrl_right_cw
        # Step 3: Expand the seed into seeds and control bits for left and
        # right child.
        (s, t) = self.extend(node.seed, nonce)
        # Step 4: Correct the seed and control bits for the nodes at the next
        # level, if the current node's control bit is set.
        if node.ctrl_bit:
            s[0] = xor(s[0], seed_cw)
            t[0] ^= ctrl_left_cw
            s[1] = xor(s[1], seed_cw)
            t[1] ^= ctrl_right_cw
        left_child = EvalNode(level=node.level + 1, seed=s[0], ctrl_bit=t[0],
                              leaf_index=node.leaf_index << 1)
        right_child = EvalNode(level=node.level + 1, seed=s[1], ctrl_bit=t[1],
                               leaf_index=(node.leaf_index << 1) | 1)
        return (left_child, right_child)

    def extend(self,
               seed: bytes,
               nonce: bytes,
               ) -> tuple[list[bytes], list[bool]]:
        '''
        Extend a seed into the seed and control bits for its left and
        right children in the VIDPF tree.
        '''
        # TODO(junyechen1996): We probably want to revisit this Xof choice in our implementation.
        xof = self.xof(seed, dst_alg(USAGE_EXTEND, self.algorithm_id), nonce)
        s = [
            bytearray(xof.next(self.KEY_SIZE)),
            bytearray(xof.next(self.KEY_SIZE)),
        ]
        # Use the least significant bits as the control bit correction,
        # and then zero it out. This gives effectively 127 bits of
        # security, but reduces the number of AES calls needed by 1/3.
        t = [bool(s[0][0] & 1), bool(s[1][0] & 1)]
        s[0][0] &= 0xFE
        s[1][0] &= 0xFE
        return ([bytes(s[0]), bytes(s[1])], t)

    def compute_leaf_level(self,
                           seed: bytes,
                           nonce: bytes) -> tuple[list[F], bytes]:
        """
        Compute the field elements and proof bytes at leaf nodes,
        expanded from the seed.
        """
        xof = self.xof(seed, dst_alg(USAGE_CONVERT, self.algorithm_id), nonce)
        vals: list[F] = xof.next_vec(self.field, self.block_size)
        # Generate another `PROOF_SIZE` bytes per section 3.2
        # "Proving k-sparsity of the output blocks" of
        # https://eprint.iacr.org/2025/490.pdf
        proof: bytes = xof.next(PROOF_SIZE)
        return (vals, proof)

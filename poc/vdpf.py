"""Preamble's DPF implementation. """

from typing import Generic, TypeAlias, TypeVar

from vdaf_poc.common import byte, front, vec_add, vec_neg, vec_sub, xor
from vdaf_poc.field import NttField
from vdaf_poc.xof import Xof

from dst import USAGE_CONVERT, USAGE_EXTEND, dst_alg

PROOF_SIZE = 32

F = TypeVar("F", bound=NttField)

LeafCorrectionWord: TypeAlias = list[F]
ProofCorrectionWord: TypeAlias = bytes


class InternalCorrectionWord:
    """
    An internal level's correction words. Not generic in the field: an
    internal node carries only a seed and control bits, since Preamble
    expands field elements at the leaf level alone.
    """

    def __init__(self, seed_cw: bytes, ctrl_bit_left: bool, ctrl_bit_right: bool):
        self.seed_cw = seed_cw
        self.ctrl_bit_left = ctrl_bit_left
        self.ctrl_bit_right = ctrl_bit_right


class CorrectionWords(Generic[F]):
    def __init__(self,
                 internal_cws: list[InternalCorrectionWord],
                 leaf_cw: LeafCorrectionWord[F],
                 proof_cw: ProofCorrectionWord):
        self.internal_cws = internal_cws
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


class Vdpf(Generic[F]):
    """The Verifiable Distributed Point Function of Preamble.

    We note that the internal node's gen and eval algorithms are very
    similar to Mastic's:
    https://github.com/jimouris/draft-mouris-cfrg-mastic/blob/main/poc/vidpf.py,
    as described in Fig. 15 and Fig. 16 of
    https://eprint.iacr.org/2023/080 except 1) Preamble doesn't track
    a value at every internal node, since our goal is to only expand
    the field elements at the leaf nodes and 2) the value in the leaf
    node is a block of field elements.
    """
    def __init__(self, field: type[F], num_leaf_nodes: int,
                 leaf_size: int, nonce_size: int, xof: type[Xof],
                 algorithm_id: int):
        self.xof = xof
        self.algorithm_id = algorithm_id
        self.KEY_SIZE = self.xof.SEED_SIZE
        self.NONCE_SIZE = nonce_size
        self.RAND_SIZE = 2 * xof.SEED_SIZE
        self.field = field
        self.num_leaf_nodes = num_leaf_nodes
        self.leaf_size = leaf_size
        self.depth = self.num_leaf_nodes.bit_length() - 1

    def gen(self,
            leaf_index: int,  # Block index as an integer.
            values: list[F],
            ctx: bytes,
            nonce: bytes,
            rand: bytes,
            ) -> tuple[CorrectionWords[F], list[bytes]]:
        '''
        Returns this DPF's correction words (the VDPF-only slice of the
        public share: the correction word for each internal level and
        leaf level of the tree, plus the proof correction word), and the
        two initial seeds, one for each Aggregator. The public share's
        other field, `joint_rand_parts`, is computed separately by the
        caller, though it binds the encoded correction words returned
        here.
        '''
        if leaf_index < 0 or leaf_index >= self.num_leaf_nodes:
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
        ctrl_bits_initial = [False, True]
        # Compute the internal-level correction words sent to both aggregators.
        internal_cws:list[InternalCorrectionWord] = []
        # Step 3: Loop through each internal level of the DPF tree.
        for i in range(self.depth):
            bit = bool((leaf_index >> (self.depth - 1 - i)) & 1)

            # Step 4: Expand PRG into seed and control bit for both aggregators.
            (s0, t0) = self.extend(seeds[0], ctx, nonce)
            (s1, t1) = self.extend(seeds[1], ctx, nonce)

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
            # Implementation note: the index `lose` is
            # `leaf_index`-dependent.
            seed_cw = xor(s0[lose], s1[lose])
            ctrl_bits = [
                t0[0] ^ t1[0] ^ (not bit),
                t0[1] ^ t1[1] ^ bit,
            ]

            # Steps 10 and 11: Correct.
            #
            # Implementation note: the index `keep` is
            # `leaf_index`-dependent, as is `ctrl`.  If the control
            # bit is set, apply the correction words.
            if ctrl_bits_initial[0]:
                s0[keep] = xor(s0[keep], seed_cw)
                t0[keep] ^= ctrl_bits[keep]
            if ctrl_bits_initial[1]:
                s1[keep] = xor(s1[keep], seed_cw)
                t1[keep] ^= ctrl_bits[keep]

            # After correction, they become next level's seeds and
            # control bits.
            seeds[0] = s0[keep]
            seeds[1] = s1[keep]
            ctrl_bits_initial[0] = t0[keep]
            ctrl_bits_initial[1] = t1[keep]

            internal_cws.append(
                InternalCorrectionWord(seed_cw, ctrl_bits[0], ctrl_bits[1]))

        # Similar to step 12 in Figure 8 in
        # https://doi.org/10.52202/085713-0680: Compute leaf
        # correction.  Sample leader and helper's random field
        # elements and also the proofs for block sparsity (see Section
        # D.1 in https://doi.org/10.52202/085713-0680) from their
        # seeds at the leaf level.  During generation, we use the full
        # path which is leaf_index (the block index).
        leaf_index_bytes = leaf_index.to_bytes((self.depth + 7) // 8, byteorder='big')
        (w0, proof0) = self.compute_leaf_level(
            seeds[0], ctx, nonce + leaf_index_bytes)
        (w1, proof1) = self.compute_leaf_level(
            seeds[1], ctx, nonce + leaf_index_bytes)
        leaf_cw = vec_add(vec_sub(values, w0), w1)

        if ctrl_bits_initial[1]:
            leaf_cw = vec_neg(leaf_cw)
        proof_cw = xor(proof0, proof1)
        return (CorrectionWords(internal_cws, leaf_cw, proof_cw),
                initial_seeds)

    def encode_correction_words(self, cws: CorrectionWords[F]) -> bytes:
        result = bytes()
        for internal_cw in cws.internal_cws:
            result += internal_cw.seed_cw
            result += byte(internal_cw.ctrl_bit_left)
            result += byte(internal_cw.ctrl_bit_right
)
        result += self.field.encode_vec(cws.leaf_cw)
        result += cws.proof_cw
        return result

    def correction_words_size(self) -> int:
        """Length of `encode_correction_words()`'s output."""
        return (self.depth * (self.KEY_SIZE + 2) +
                self.field.ENCODED_SIZE * self.leaf_size +
                PROOF_SIZE)

    def decode_correction_words(self, encoded: bytes) -> CorrectionWords[F]:
        if len(encoded) != self.correction_words_size():
            raise ValueError("correction words have incorrect length")
        internal_cws = []
        for _ in range(self.depth):
            (seed_cw, encoded) = front(self.KEY_SIZE, encoded)
            (ctrl_bits, encoded) = front(2, encoded)
            if any(b > 1 for b in ctrl_bits):
                raise ValueError("invalid control bit")
            internal_cws.append(InternalCorrectionWord(
                seed_cw, bool(ctrl_bits[0]), bool(ctrl_bits[1])))
        (leaf_bytes, encoded) = front(
            self.field.ENCODED_SIZE * self.leaf_size, encoded)
        leaf_cw = self.field.decode_vec(leaf_bytes)
        return CorrectionWords(internal_cws, leaf_cw, encoded)

    def eval_all(self,
                 ctx: bytes,
                 nonce: bytes,
                 agg_id: int,
                 initial_seed: bytes,
                 initial_ctrl_bit: bool,
                 cws: CorrectionWords[F],
                 ) -> tuple[list[F], list[bytes]]:
        """
        Evaluate the field elements expanded from the leaf nodes.  The
        evaluation algorithm is very similar to standard DPF
        evaluation, except we will evaluate all the leaf nodes and
        expand them into secret shares of the original client vector.

        Every leaf contributes its full `leaf_size` field elements, so the
        result always has exactly `num_leaf_nodes * leaf_size` many field elements.
        """
        root_node = EvalNode(level=0, seed=initial_seed, ctrl_bit=initial_ctrl_bit)
        if self.depth == 0:
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
                ctx, nonce, node, cws.internal_cws)
            if node.level < self.depth - 1:
                internal_nodes.append(left_child)
                internal_nodes.append(right_child)
            else:
                leaf_nodes.append(left_child)
                leaf_nodes.append(right_child)

        assert len(leaf_nodes) == self.num_leaf_nodes
        field_elems: list[F] = []
        proofs: list[bytes] = []
        for leaf_node in leaf_nodes:
            leaf_index_bytes = leaf_node.leaf_index.to_bytes(
                (self.depth + 7) // 8, byteorder='big')
            (w, proof) = self.compute_leaf_level(
                leaf_node.seed, ctx, nonce + leaf_index_bytes)
            if leaf_node.ctrl_bit:
                w = vec_add(w, cws.leaf_cw)
                proof = xor(proof, cws.proof_cw)
            if agg_id == 1:
                # Helper negates its share.
                w = vec_neg(w)
            field_elems.extend(w)
            proofs.append(proof)
        return field_elems, proofs

    def eval_next_children(self,
                           ctx: bytes,
                           nonce: bytes,
                           node: EvalNode,
                           internal_cw_list: list[InternalCorrectionWord],
                           ) -> tuple[EvalNode, EvalNode]:
        """
        Evaluate the next and right child of the current `node`.
        The evaluation algorithm is very similar to Mastic's evaluation:
        https://github.com/jimouris/draft-mouris-cfrg-mastic/blob/main/poc/vidpf.py
        as described in Fig. 16 in https://eprint.iacr.org/2023/080
        """
        # Step 2: Get current level's seed and control bit correction words.
        seed_cw = internal_cw_list[node.level].seed_cw
        ctrl_left_cw = internal_cw_list[node.level].ctrl_bit_left
        ctrl_right_cw = internal_cw_list[node.level].ctrl_bit_right

        # Step 3: Expand the seed into seeds and control bits for left and
        # right child.
        (s, t) = self.extend(node.seed, ctx, nonce)
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
               ctx: bytes,
               nonce: bytes,
               ) -> tuple[list[bytes], list[bool]]:
        '''
        Extend a seed into the seed and control bits for its left and
        right children in the VDPF tree.
        '''

        xof = self.xof(
            seed, dst_alg(USAGE_EXTEND, self.algorithm_id, ctx), nonce)
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
                           ctx: bytes,
                           nonce: bytes) -> tuple[list[F], bytes]:
        """
        Compute the field elements and proof bytes at leaf nodes,
        expanded from the seed.
        """
        xof = self.xof(
            seed, dst_alg(USAGE_CONVERT, self.algorithm_id, ctx), nonce)
        vals: list[F] = xof.next_vec(self.field, self.leaf_size)
        # Generate another `PROOF_SIZE` bytes per section D.1
        # "Proving k-sparsity of the output blocks" of
        # https://doi.org/10.52202/085713-0680
        proof: bytes = xof.next(PROOF_SIZE)
        return (vals, proof)

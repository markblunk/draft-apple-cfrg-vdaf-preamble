import itertools
import unittest

from vdaf_poc.common import gen_rand, vec_add
from vdaf_poc.field import Field64
from vdaf_poc.xof import XofTurboShake128

from vdpf import EvalNode, Vdpf


class TestVdpf(unittest.TestCase):
    NONCE_SIZE = 16
    PREAMBLE_ALGORITHM_ID = 0xFFFF100

    def test_gen_eval_happy_depth_one(self):
        self.run_gen_eval(num_leaf_nodes=2,
                          leaf_size=1,
                          block_index=1,
                          block_content=[1])

    def test_gen_eval_happy_depth_two(self):
        self.run_gen_eval(num_leaf_nodes=4,
                          leaf_size=1,
                          block_index=2,
                          block_content=[1])

    def test_gen_eval_happy_depth_two_leaf_size_two(self):
        self.run_gen_eval(num_leaf_nodes=2,
                          leaf_size=2,
                          block_index=1,
                          block_content=[0, 1])

    def test_gen_eval_happy_depth_three(self):
        self.run_gen_eval(num_leaf_nodes=8,
                          leaf_size=1,
                          block_index=1,
                          block_content=[1])

    def test_gen_eval_happy_depth_three_leaf_size_two(self):
        self.run_gen_eval(num_leaf_nodes=4,
                          leaf_size=2,
                          block_index=1,
                          block_content=[1, 0])

    def run_gen_eval(self,
                     num_leaf_nodes: int,
                     leaf_size: int,
                     block_index: int,
                     block_content: list[int]):
        vdpf = Vdpf(Field64, num_leaf_nodes, leaf_size,
                                     self.NONCE_SIZE,
                                     algorithm_id=self.PREAMBLE_ALGORITHM_ID,
                                     xof=XofTurboShake128)
        ctx = b'some application'
        nonce = gen_rand(vdpf.NONCE_SIZE)
        rand = gen_rand(vdpf.RAND_SIZE)
        alpha: list[bool] = []
        curr_block_index = block_index
        for i in range(vdpf.depth):
            alpha.insert(0, bool(curr_block_index % 2))
            curr_block_index //= 2
        leaf_index = 0
        for b in alpha:
            leaf_index = (leaf_index << 1) | int(b)
        expected_vector = []
        for i in range(num_leaf_nodes):
            if i == block_index:
                expected_vector.extend(block_content)
            else:
                expected_vector.extend([0] * leaf_size)
        print(f"block index = {block_index}, alpha = {alpha}, "
              f"expected vector = {expected_vector}")

        block_field_elems = [vdpf.field(v) for v in block_content]
        (cws, initial_seeds) = vdpf.gen(
            leaf_index, block_field_elems, ctx, nonce, rand)

        # Verify DPF invariants, i.e., in the "on" path, leader and helper
        # evaluate to different seeds and different control bits, and in the
        # "off" path, they evaluate to the same seeds and control bits.
        for curr_alpha in list(itertools.product([False, True],
                                                 repeat=vdpf.depth)):
            leader_root_node = EvalNode(level=0,
                                        seed=initial_seeds[0],
                                        ctrl_bit=False)
            helper_root_node = EvalNode(level=0,
                                        seed=initial_seeds[1],
                                        ctrl_bit=True)
            leader_node = leader_root_node
            helper_node = helper_root_node
            curr_prefix = []
            for bit in curr_alpha:
                curr_prefix.append(bit)
                leader_node = vdpf.eval_next_children(
                    ctx, nonce, leader_node, cws.internal_cws)[bit]
                helper_node = vdpf.eval_next_children(
                    ctx, nonce, helper_node, cws.internal_cws)[bit]
                if TestVdpf.is_prefix(curr_prefix, alpha):
                    # On path, leader and helper should evaluate to different
                    # seeds and control bits.
                    self.assertNotEqual(leader_node.seed, helper_node.seed)
                    self.assertNotEqual(leader_node.ctrl_bit,
                                        helper_node.ctrl_bit)
                else:
                    # Off path, leader and helper should evaluate to the same
                    # seed and control bit.
                    self.assertEqual(leader_node.seed, helper_node.seed)
                    self.assertEqual(leader_node.ctrl_bit, helper_node.ctrl_bit)

        # Now check the secret shares sum up to the original client vector.
        # Leader's eval:
        (leader_field_elems, leader_proofs) = vdpf.eval_all(
            ctx, nonce, 0, initial_seeds[0], False, cws)
        # Helper's eval:
        (helper_field_elems, helper_proofs) = vdpf.eval_all(
            ctx, nonce, 1, initial_seeds[1], True, cws)
        recovered_field_elems = vec_add(leader_field_elems, helper_field_elems)
        recovered_vector = [e.int() for e in recovered_field_elems]
        self.assertEqual(expected_vector, recovered_vector)

        for (leader_proof, helper_proof) in zip(leader_proofs, helper_proofs):
            assert leader_proof == helper_proof

    @staticmethod
    def is_prefix(prefix: list[bool], alpha: list[bool]) -> bool:
        for i in range(len(prefix)):
            if prefix[i] != alpha[i]:
                return False
        return True


class RecordingVdpf(Vdpf):
    """Records the binder of every leaf-level expansion."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.leaf_binders: list[bytes] = []

    def compute_leaf_level(self, seed, ctx, nonce):
        self.leaf_binders.append(nonce)
        return super().compute_leaf_level(seed, ctx, nonce)


class TestVdpfLeafIdentity(unittest.TestCase):


    def check(self, num_leaf_nodes: int, leaf_index: int):
        vdpf = RecordingVdpf(Field64, num_leaf_nodes, 1, 16, XofTurboShake128,
                               algorithm_id=0xFFFF100)
        ctx = b'some application'
        nonce = gen_rand(vdpf.NONCE_SIZE)
        width = (vdpf.depth + 7) // 8

        def binder(i: int) -> bytes:
            return nonce + i.to_bytes(width, byteorder='big')

        (cws, seeds) = vdpf.gen(leaf_index, [Field64(1)], ctx, nonce,
                                 gen_rand(vdpf.RAND_SIZE))
        # Both Aggregators' shares of the chosen leaf.
        self.assertEqual(vdpf.leaf_binders, [binder(leaf_index)] * 2)

        for (agg_id, ctrl_bit) in [(0, False), (1, True)]:
            vdpf.leaf_binders = []
            vdpf.eval_all(ctx, nonce, agg_id, seeds[agg_id], ctrl_bit, cws)
            # Every leaf, left to right, each under its own index.
            self.assertEqual(vdpf.leaf_binders,
                             [binder(i) for i in range(num_leaf_nodes)])

    def test_single_leaf(self):
        # Depth 0: the index takes no bytes, so the binder is the nonce.
        self.check(num_leaf_nodes=1, leaf_index=0)

    def test_one_byte_index(self):
        self.check(num_leaf_nodes=8, leaf_index=5)

    def test_two_byte_index(self):
        # Depth 9 needs a second byte; the index is right-aligned.
        self.check(num_leaf_nodes=512, leaf_index=300)

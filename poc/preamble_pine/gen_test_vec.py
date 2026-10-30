import os

from vdaf_poc.test_utils import gen_test_vec_for_vdaf

from vdaf_pine_poc.xof_hmac_sha256_aes128 import XofHmacSha256Aes128
from vdaf_pine_poc.field import Field32

from preamble_pine import Preamble

dir_name = os.path.dirname(os.path.abspath(__file__))
VERSION = int(open(os.path.join(dir_name, 'VERSION')).read())
TEST_VECTOR_PATH = os.environ.get('TEST_VECTOR_PATH',
                                  os.path.join(dir_name,
                                               'test_vec/{:02}'.format(VERSION)))
if __name__ == '__main__':
    chunk_length = 150
    chunk_length_norm_equality = 4
    l2_norm_bound = 8
    dimension = 16
    block_size = 4
    num_kept_blocks = 2
    measurements = [
                # Falls into block 0 and 2 of the vector space.
                [([False], [1, 0, 0, 1]), ([False], [1, 1, 1, 1])],
                # Falls into block 1 and 2 of the vector space.
                [([True], [0, 1, 1, 0]), ([False], [0, 1, 1, 1])],
                # Falls into block 0 and 3 of the vector space.
                [([False], [1, 0, 0, 0]), ([True], [0, 1, 1, 1])]
            ]
    # agg_result = [2, 0, 0, 1, 0, 1, 1, 0, 1, 2, 2, 2, 0, 1, 1, 1]

    gen_test_vec_for_vdaf(
        TEST_VECTOR_PATH,
        Preamble(field=Field32,
                 dimension=dimension,
                 block_size=block_size,
                 num_kept_blocks=num_kept_blocks,
                 l2_norm_bound=l2_norm_bound,
                 chunk_length=chunk_length,
                 chunk_length_norm_equality=chunk_length_norm_equality,
                 xof=XofHmacSha256Aes128),

        None,
        measurements,
        1,
        True)

    measurements = [[([False], [1, 1]),
                     ([False], [1, 0])],
                    [([True], [0, 1]),
                     ([True], [1, 1])],
                    [([False], [1, 0]),
                     ([True], [0, 1])]]
    # agg_result: [2, 1, 0, 1, 1, 0, 1, 2]
    gen_test_vec_for_vdaf(
        TEST_VECTOR_PATH,
        Preamble(field=Field32,
                 dimension=8,
                 block_size=2,
                 num_kept_blocks=2,
                 l2_norm_bound=2,
                 chunk_length=1,
                 chunk_length_norm_equality=2,
                 xof=XofHmacSha256Aes128),
        None,
        measurements,
        2,
        True)

    # `dimension % block_size != 0` (global padding):
    # dim=9, block_size=2, num_kept_blocks=2 → padded_super_block_size=8.
    # SB 0 covers buffer [0, 8); SB 1 covers [8, 16) of which only buffer
    # position 8 is in dim. The caller still supplies a block per SB; the
    # SB-1 block's tail (coord 9 onward) must be zero.
    measurements = [
        # SB 0 prefix=0 (coords 0, 1): value 1 at coord 0.
        # SB 1 prefix=0 (coords 8, 9): value 1 at coord 8.
        [([False, False], [1, 0]), ([False, False], [1, 0])],
        # SB 0 prefix=2 (coords 4, 5): value 1 at coord 5.
        # SB 1 prefix=0 (coords 8, 9): value 1 at coord 8.
        [([True, False], [0, 1]), ([False, False], [1, 0])],
        # SB 0 prefix=1 (coords 2, 3): values 1, 1.
        # SB 1 prefix=0 (coords 8, 9): value 1 at coord 8.
        [([False, True], [1, 1]), ([False, False], [1, 0])],
    ]
    # agg_result: [1, 0, 1, 1, 0, 1, 0, 0, 3]
    gen_test_vec_for_vdaf(
        TEST_VECTOR_PATH,
        Preamble(field=Field32,
                 dimension=9,
                 block_size=2,
                 num_kept_blocks=2,
                 l2_norm_bound=2,
                 chunk_length=1,
                 chunk_length_norm_equality=4,
                 xof=XofHmacSha256Aes128),
        None,
        measurements,
        3,
        True)

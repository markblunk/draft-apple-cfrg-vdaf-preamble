import unittest
from random import randrange

from vdaf_poc.common import from_be_bytes, gen_rand
from vdaf_poc.field import Field64
from vdaf_poc.test_utils import TestVdaf

from preamble_pine import Preamble


class TestPreamble(TestVdaf):
    def test_single_super_block(self):
        p = Preamble(field=Field64,
                     dimension=1,
                     block_size=1,
                     num_kept_blocks=1,
                     l2_norm_bound=2,
                     chunk_length=1,
                     chunk_length_norm_equality=1)
        self.run_vdaf_test(
            p,
            None,
            [
                [([], [1])],
                [([], [1])],
                [([], [0])],
            ],
            [2]
        )

        p = Preamble(field=Field64,
                     dimension=2,
                     block_size=1,
                     num_kept_blocks=1,
                     l2_norm_bound=2,
                     chunk_length=1,
                     chunk_length_norm_equality=1)
        self.run_vdaf_test(
            p,
            None,
            [
                [([False], [1])],
                [([True], [1])],
                [([True], [1])],
            ],
            [1, 2]
        )

        p = Preamble(field=Field64,
                     dimension=16,
                     block_size=4,
                     num_kept_blocks=1,
                     l2_norm_bound=2,
                     chunk_length=1,
                     chunk_length_norm_equality=4)
        self.run_vdaf_test(
            p,
            None,
            [
                # Falls into the first block of the vector space.
                [([False, False], [1, 0, 0, 1])],
                # Falls into the second block of the vector space.
                [([False, True], [0, 1, 1, 0])],
                # Falls into the last block of the vector space.
                [([True, True], [1, 0, 0, 0])]
            ],
            [1, 0, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0]
        )

    def test_two_super_blocks(self):
        p = Preamble(field=Field64,
                     dimension=2,
                     block_size=1,
                     num_kept_blocks=2,
                     l2_norm_bound=2,
                     chunk_length=1,
                     chunk_length_norm_equality=1)
        self.run_vdaf_test(
            p,
            None,
            [
                [([], [1]), ([], [1])],
                [([], [1]), ([], [1])],
                [([], [0]), ([], [1])]
            ],
            [2, 3]
        )

        p = Preamble(field=Field64,
                     dimension=16,
                     block_size=4,
                     num_kept_blocks=2,
                     l2_norm_bound=3,
                     chunk_length=1,
                     chunk_length_norm_equality=4)
        self.run_vdaf_test(
            p,
            None,
            [
                # Falls into block 0 and 2 of the vector space.
                [([False], [1, 0, 0, 1]), ([False], [1, 1, 1, 1])],
                # Falls into block 1 and 2 of the vector space.
                [([True], [0, 1, 1, 0]), ([False], [0, 1, 1, 1])],
                # Falls into block 0 and 3 of the vector space.
                [([False], [1, 0, 0, 0]), ([True], [0, 1, 1, 1])]
            ],
            [2, 0, 0, 1, 0, 1, 1, 0, 1, 2, 2, 2, 0, 1, 1, 1]
        )

    def test_dimension_not_multiple_of_block_size(self):
        # dimension=9, block_size=2, num_kept_blocks=2 (global padding):
        # padded_super_block_size = next_pow2(ceil(9/(2*2))) * 2 = 4*2 = 8.
        # SB 0 covers buffer positions [0, 8); SB 1 covers [8, 16). The user
        # vector occupies [0, 9), so SB 0 is fully in dim and SB 1 has only
        # buffer position 8 in dim — its remaining seven positions are
        # trailing padding. The caller still supplies a block for SB 1, but
        # they must arrange the values so anything past coord 8 is zero
        # (otherwise the truncated `prep_init` reconstruction won't match
        # what the PINE proof commits to).
        p = Preamble(field=Field64,
                     dimension=9,
                     block_size=2,
                     num_kept_blocks=2,
                     l2_norm_bound=2,
                     chunk_length=1,
                     chunk_length_norm_equality=4)
        self.run_vdaf_test(
            p,
            None,
            [
                # SB 0 prefix=0 (coords 0, 1) value 1 at coord 0;
                # SB 1 prefix=0 (coords 8, 9) value 1 at coord 8 (coord 9 is
                # trailing padding, must be 0).
                [([False, False], [1, 0]), ([False, False], [1, 0])],
                # SB 0 prefix=2 (coords 4, 5) value 1 at coord 5;
                # SB 1 prefix=0 (coords 8, 9) value 1 at coord 8.
                [([True, False], [0, 1]), ([False, False], [1, 0])],
                # SB 0 prefix=1 (coords 2, 3) values 1, 1;
                # SB 1 prefix=0 (coords 8, 9) value 1 at coord 8.
                [([False, True], [1, 1]), ([False, False], [1, 0])],
            ],
            [1, 0, 1, 1, 0, 1, 0, 0, 3],
        )

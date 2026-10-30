import os

from vdaf_poc.field import Field128
from vdaf_poc.test_utils import gen_test_vec_for_vdaf

from preamble import (PreambleCount, PreambleL1BoundSum,
                      PreambleMeasurement, PreambleMultihotCountVec,
                      PreambleSumVec)

dir_name = os.path.dirname(os.path.abspath(__file__))
VERSION = int(open(os.path.join(dir_name, 'VERSION')).read())
TEST_VECTOR_PATH = os.environ.get('TEST_VECTOR_PATH',
                                  os.path.join(dir_name,
                                               'test_vec/{:02}'.format(VERSION)))
if __name__ == '__main__':
    # MultihotCountVec: a Client submits one counter per coordinate of its
    # chosen block, at most `max_weight` of them set, so the aggregate
    # counts, per block, how many Clients set each coordinate. The block the
    # VDPF carries is one element longer than `block_size`: `max_weight ==
    # 1` takes a single bit to report, and `flp.truncate()` drops it before
    # aggregation.
    measurements:list[PreambleMeasurement] = [
        # Coordinate 0 of block 0 of the vector space.
        ((False, False), [1, 0, 0]),
        # Coordinate 2 of block 0.
        ((False, False), [0, 0, 1]),
        # Coordinate 1 of block 2.
        ((True, False), [0, 1, 0]),
    ]
    # agg_result = [[1, 0, 1], [0, 0, 0], [0, 1, 0], [0, 0, 0]]
    gen_test_vec_for_vdaf(
        TEST_VECTOR_PATH,
        PreambleMultihotCountVec(field=Field128,
                                 dimension=12,
                                 block_size=3,
                                 max_weight=1,
                                 chunk_length=2),
        None,
        b"some application",
        measurements,
        1,
        True)

    # SumVec with `bits == 1`: a Client submits one bit per coordinate of
    # its chosen block, so the aggregate counts, per block, how many
    # Clients set each coordinate.
    measurements = [((False, False), [1, 1]),
                    ((True, True), [0, 1]),
                    ((False, True), [1, 0])]
    # agg_result: [[1, 1], [1, 0], [0, 0], [0, 1]]
    gen_test_vec_for_vdaf(
        TEST_VECTOR_PATH,
        PreambleSumVec(field=Field128,
                      dimension=8,
                      block_size=2,
                      chunk_length=2),
        None,
        b"some application",
        measurements,
        1,
        True)
    count_measurements: list[PreambleMeasurement] = [
        ((False, False), 1),
        ((True, False), 1),
        ((False, False), 1),
        ((True, True), 0),
    ]
    # agg_result: [2, 0, 1, 0]
    gen_test_vec_for_vdaf(
        TEST_VECTOR_PATH,
        PreambleCount(field=Field128, dimension=4),
        None,
        b"some application",
        count_measurements,
        1,
        True)
    l1_measurements: list[PreambleMeasurement] = [
        ((False, False), [1, 2, 3]),
        ((True, False), [6, 0, 0]),
        ((False, False), [0, 4, 2]),
    ]
    # agg_result: [[1, 6, 5], [0, 0, 0], [6, 0, 0], [0, 0, 0]]
    gen_test_vec_for_vdaf(
        TEST_VECTOR_PATH,
        PreambleL1BoundSum(field=Field128,
                           dimension=12,
                           block_size=3,
                           max_value=6,
                           chunk_length=3),
        None,
        b"some application",
        l1_measurements,
        1,
        True)

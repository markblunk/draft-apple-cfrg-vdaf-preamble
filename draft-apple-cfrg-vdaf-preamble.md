---
title: "The PREAMBLE VDAF"
abbrev: "PREAMBLE"
category: info

docname: draft-apple-cfrg-vdaf-preamble-latest
submissiontype: IRTF
number:
date:
consensus: true
v: 3
area: "IRTF"
workgroup: "Crypto Forum"
keyword:
  - VDAF
  - privacy-preserving aggregation
  - block-sparse vectors
venue:
  group: "Crypto Forum"
  type: "Research Group"
  mail: "cfrg@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/search/?email_list=cfrg"
  github: "markblunk/draft-apple-cfrg-vdaf-preamble"
  latest: "https://markblunk.github.io/draft-apple-cfrg-vdaf-preamble.html"

author:
 -
    ins: M. Blunk
    fullname: Mark Blunk
    organization: Apple Inc.
    email: mblunk@apple.com
 -
    ins: J. Chen
    fullname: Junye Chen
    organization: Apple Inc.
    email: junyec@apple.com
 -
    ins: P. Jain
    fullname: Palak Jain
    organization: Apple Inc.
    email: palak_jain@apple.com

normative:

  Prio3L1BoundSum: I-D.draft-ietf-ppm-l1-bound-sum-02
  VDAF: I-D.draft-irtf-cfrg-vdaf-18

informative:

  Mastic: I-D.draft-mouris-cfrg-mastic-04
  PINE: I-D.draft-chen-cfrg-vdaf-pine-02

  BBCGGI19:
    title: "Zero-Knowledge Proofs on Secret-Shared Data via Fully Linear PCPs"
    author:
      - ins: D. Boneh
      - ins: E. Boyle
      - ins: H. Corrigan-Gibbs
      - ins: N. Gilboa
      - ins: Y. Ishai
    date: 2019
    seriesinfo: CRYPTO 2019
    target: https://ia.cr/2019/188

  DP22:
    title: "Lightweight, Maliciously Secure Verifiable Function Secret Sharing"
    author:
      - ins: L. deCastro
      - ins: A. Polychroniadou
    date: 2022
    seriesinfo: EUROCRYPT 2022
    target: https://doi.org/10.1007/978-3-031-06944-4_6

  PREAMBLE:
    title: "PREAMBLE: Private and Efficient Aggregation via Block Sparse Vectors"
    author:
      - ins: H. Asi
      - ins: V. Feldman
      - ins: H. Keller
      - ins: G. Rothblum
      - ins: K. Talwar
    date: 2025
    target: https://arxiv.org/abs/2503.11897

...

--- abstract

This document describes PREAMBLE, a two-party Verifiable Distributed Aggregation
Function (VDAF) for secure aggregation where each client holds a
large-dimensional vector that is *block-sparse*, meaning it is divided into
fixed-size blocks of which at most one is nonzero, and that nonzero block itself
satisfies a specified Fully Linear Proof (such as multihot, or a bounded L1 or
L2 norm).

--- middle

# Introduction

(RFC EDITOR: Remove this paragraph.) The source for this draft and the reference
code can be found at
https://github.com/markblunk/draft-apple-cfrg-vdaf-preamble.

Prio3 {{VDAF}} is a widely deployed protocol used in the aggregation of
federated statistics: each client secret-shares a measurement (such as a binary
value or a vector of integers) among a set of Aggregators, who jointly verify
that it is well-formed before contributing its shares to an aggregate. PINE
{{PINE}} adapts this same approach to federated machine learning, where each
client's measurement is instead a gradient, and the Aggregators additionally
verify that its L2 norm is bounded, so that no one client's update can
disproportionately affect the trained model. In both constructions, the cost of
sharding, verifying, and aggregating a measurement scales linearly with its
dimension and can become impractical for vectors of large dimension, for
example, in the millions.

Verifiable Distributed Point Functions (VDPF), as defined in {{DP22}} address
this issue for a different class of high-dimensional problems. Poplar1
({{Section 8 of VDAF}}) and Mastic {{Mastic}} use a similar functionality to let
a client secret-share a single point in a large domain (such as the location of
a *heavy hitter* input for Poplar1, or an input together with an associated
weight for Mastic), so that the verification and aggregation cost is governed by
the depth of the distributed point function's evaluation tree rather than by the
size of the domain itself.

This document describes PREAMBLE, a two-party Verifiable Distributed Aggregation
Function (VDAF) that combines both ideas, following {{PREAMBLE}}, to aggregate
*block-sparse* vectors. Under this approach, a client's measurement, a vector of
large dimension, is divided into fixed-size blocks, at most one of which may be
nonzero.  PREAMBLE secret-shares this measurement without revealing which block
is nonzero or what it contains. It also provides a proof to verify that 1) at
most one block is nonzero; and 2) the contents of that block satify a property
that can be checked by an associated Fully Linear Proof (FLP) supplied as a
parameter (see {{Section 7 of VDAF}}). Section {{vdaf}} specifies this generic
composition of VDPF and FLP, and {{variants}} instantiates it with concrete
FLPs.  PREAMBLE's communication cost scales with the block size and the depth of
the VDPF's tree (logarithmic in the number of blocks) rather than with the
dimension of the vector itself. The server-side cost of verification and
aggregation still scales linearly with the dimension.

For example, consider a service that reports what kinds of photos people take at
popular locations. The map is divided into a grid of about a million (2^20)
tiles, and each tile is assigned a block of 100 counters, one per photo category
such as *sky*, *person*, or *recreation*, for a total dimension of roughly 100
million. Because the photos a client contributes in one collection period tend
to be taken in one geographic tile, its measurement touches a small number of
indices that could be contained in a small block: the block index identifies the
tile, and the block content records which categories appear there, which a
multihot FLP can limit to a small number. With PREAMBLE, the client's upload is
dominated by the 100-entry block and grows only logarithmically with the number
of blocks (the 20 levels of the VDPF tree). The Aggregators' verification work,
by contrast, still grows linearly with the dimension: they must evaluate the
VDPF down to every leaf and expand the secret shares of every coordinate there,
before summing the blocks elementwise and running the FLP on the sum.

Another example comes from distributed model training, where each client
contributes a locally computed gradient. For models with millions or hundreds of
millions of parameters, the communication cost of sending a dense gradient is
prohibitive. Recent work shows while model training is global over all parameter
each individual client need only share the training result on a subset of the
parameters.  PREAMBLE suits this setting, especially when a regularity
condition, such as a bounded Euclidean (L2) norm, is also enforced on the
nonzero block.

# Conventions and Definitions {#conventions}

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD",
"SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this
document are to be interpreted as described in BCP 14 {{!RFC2119}} {{!RFC8174}}
when, and only when, they appear in all capitals, as shown here.

* Clients, Aggregators, and Collectors from {{Section 3 of VDAF}}.

* Auxiliary functions from {{Section 2 of VDAF}}.

| Functionality | Type     | Definition |
|:--------------|:---------|:-----------|
| `concat`      | Function | Section 2  |
| `front`       | Function | Section 2  |
| `to_be_bytes` | Function | Section 2  |
| `xor`         | Function | Section 2  |
| `zeros`       | Function | Section 2  |
{: #aux-functionalities title="Auxiliary functionalities"}

* Finite fields from {{Section 6.1 of VDAF}}.

| Functionality | Type         | Definition    |
|:--------------|:-------------|:--------------|
| `field.zeros` | Class Method | Section 6.1   |
| `vec_add`     | Function     | Section 6.1.1 |
| `vec_sub`     | Function     | Section 6.1.1 |
| `vec_neg`     | Function     | Section 6.1.1 |
{: #field-functionalities title="Finite field functionalities"}

* Extendable-Output Functions (XOFs) from {{Section 6.2 of VDAF}}.

| Functionality         | Type            |
|:----------------------|:----------------|
| `XofTurboShake128`    | Constructor     |
| `xof.next`            | Instance Method |
| `xof.derive_seed`     | Class Method    |
| `xof.expand_into_vec` | Class Method    |
| `xof.SEED_SIZE`       | Class Attribute |
{: #xof-functionalities title="XOF functionalities"}


## Domain Separation {#dst}

Each invocation of an XOF is initialized with a domain separation tag built by
`dst_alg()` below, which encodes the version of this document, an algorithm
class byte, the 4-byte PREAMBLE algorithm identifier ({{Section 5 of VDAF}}),
and a 2-byte code identifying how the XOF output is used.

The version of this document is a byte denoted `VERSION`. Its value SHALL be
`0`. The algorithm class byte is denoted `ALG_CLASS` and SHALL be `0`.

> NOTE We'll bump `VERSION` whenever we publish a draft with incompatible
> changes from the previous draft.


Algorithms in the remainder use the following helper:

~~~ python
def dst_alg(usage: int, algorithm_id: int, ctx: bytes) -> bytes:
    assert usage in range(14)
    assert algorithm_id in range(2 ** 32)
    return byte(VERSION) \
        + byte(ALG_CLASS) \
        + to_be_bytes(algorithm_id, 4) \
        + to_be_bytes(usage, 2) \
        + ctx
~~~

{{dst-usage}} lists the usage codes referenced in the remainder of this
document. Codes `2`-`7` are reused, unmodified, from Prio3's own domain
separation scheme ({{Section 7.2 of VDAF}}); codes `11`-`13` are defined by
this document. Prio3's code `1` (`USAGE_MEAS_SHARE`) is not used: PREAMBLE has
no measurement share, because the FLP's encoded measurement is exactly the VDPF
block ({{overview}}). Codes `3`, `6`, and `7` are derived only if
`flp.JOINT_RAND_LEN > 0`. Codes `8`-`10` are RESERVED for future use and are not
derived by this document.

| Code | Usage                                                                      | Reused from Prio3? |
|:-----|:---------------------------------------------------------------------------|:-------------------|
| 2    | `USAGE_PROOF_SHARE`: expanding a proof-share seed                          | yes                |
| 3    | `USAGE_JOINT_RANDOMNESS`: expanding the joint randomness                   | yes                |
| 4    | `USAGE_PROVE_RANDOMNESS`: expanding the prover's randomness                | yes                |
| 5    | `USAGE_QUERY_RANDOMNESS`: expanding the verifier's query randomness        | yes                |
| 6    | `USAGE_JOINT_RAND_SEED`: deriving the joint randomness seed from its parts | yes                |
| 7    | `USAGE_JOINT_RAND_PART`: deriving a party's joint randomness part          | yes                |
| 8-10 | RESERVED; not derived by this document                                     | no                 |
| 11   | `USAGE_EXTEND`: expanding a VDPF internal-node seed ({{vdpf-aux}})         | no                 |
| 12   | `USAGE_CONVERT`: expanding a VDPF leaf-node seed ({{vdpf-aux}})            | no                 |
| 13   | `USAGE_ONEHOT_CHECK`: hashing the VDPF sparsity proofs together            | no                 |
{: #dst-usage title="XOF usage codes"}

# PREAMBLE Overview {#overview}

An instance of PREAMBLE is parameterized by a `dimension` and a `block_size`
such that `dimension = 2^depth * block_size` for some `depth >= 0`, and an
FLP-like circuit (see {{flp}}) that checks one block's contents. Here `depth` is
the length of a root-to-leaf path in the VDPF tree that carries the
measurement, not counting the root, so the vector has `2^depth` blocks, one per
leaf ({{vdpf}}). A Client's measurement is a `dimension`-length vector, divided
into blocks of `block_size` coordinates each, of which the Client designates
exactly one as nonzero:

~~~
+------+------+------+------+------+------+------+------+
|  0   |  0   |  B   |  0   |  0   |  0   |  0   |  0   |
+------+------+------+------+------+------+------+------+
   each block has `block_size` coordinates; `B` is the one nonzero
   block
~~~
{: #block-sparse-diagram title="A block-sparse measurement"}

PREAMBLE proves two things about this measurement:

1. Sparsity: at most one block is nonzero. This is proven by the
   one-block-sparse VDPF of {{vdpf}}, which also secret-shares the
   measurement's contents to the Aggregators.

1. Block validity: the contents of the one nonzero block, a vector of
   `block_size` coordinates, satisfy the property checked by the chosen FLP's
   circuit (see {{vdaf}}). {{variants}} defines four instantiations of this,
   PreambleCount, PreambleMultihotCountVec, PreambleSumVec, and
   PreambleL1BoundSum.

The block is encoded with `flp.encode()` and secret-shared following the FLP.
Aggregation then proceeds as expected: each Aggregator locally sums, across
Clients, its share of every block's *aggregatable* form (the `flp.OUTPUT_LEN`
field elements that `flp.truncate()` maps an encoded block to) and the
Collector sums the Aggregators' shares and decodes each block. The aggregate
result (of size `2^depth * flp.OUTPUT_LEN`) is therefore one decoded result per
block, in block order.

# Specification of the One-Block-Sparse VDPF {#vdpf}

| Parameter             | Description                                              | Value                                  |
|:----------------------|:---------------------------------------------------------|:---------------------------------------|
| `KEY_SIZE: int`       | the size of each VDPF key                                | `XOF.SEED_SIZE`                        |
| `NONCE_SIZE: int`     | the size of the report nonce                             | `16`                                   |
| `RAND_SIZE: int`      | the number of random bytes consumed by `gen()`           | `2 * KEY_SIZE`                         |
| `PROOF_SIZE: int`     | the size of the sparsity proof                           | `32`                                   |
| `leaf_size: int`      | the number of field elements carried per block           | `flp.MEAS_LEN` ({{vdaf}})              |
| `num_leaf_nodes: int` | the number of leaves in the bottom level of the tree     | `dimension / block_size`, a power of 2 |
| `depth: int`          | the length of a root-to-leaf path, not counting the root | `num_leaf_nodes.bit_length() - 1`      |
{: #vdpf-params title="One-block-sparse VDPF parameters"}

This section specifies a Verifiable Distributed Point Function for the
one-block-sparse functionality: the key generation algorithm ({{vdpf-key-gen}})
takes one block's *encoded* form (a vector of `leaf_size`-many field elements,
as determined by the underlying FLP) together with a `leaf_index` identifying
which of the `num_leaf_nodes` leaves it belongs to, and produces Aggregators'
key shares. Evaluating those keys at every leaf ({{vdpf-key-eval}}) gives each
Aggregator `leaf_size`-many field elements and one sparsity proof per leaf;
combined across the two Aggregators, the field elements equal the original
encoded block at `leaf_index` and the zero vector at every other leaf, and the
proofs let the Aggregators jointly verify that this one-block-sparse shape
holds, all without either Aggregator learning `leaf_index` or the encoded block.

The VDPF is agnostic to what the field elements of a block mean: it carries
`flp.MEAS_LEN` of them per block ({{overview}}).

## Key Generation {#vdpf-key-gen}

The key generation algorithm is run by the Client. Its inputs are `leaf_index:
int` (an integer in `[0, num_leaf_nodes)` identifying which block is nonzero,
that is, the *path* through the tree, encoded as a bit tuple), `values: list[F]`
(the nonzero block's encoded contents), the report `nonce`, and `RAND_SIZE`
bytes of randomness. Its outputs are the VDPF-related portion of the public
share, denoted `CorrectionWords`, and two private input shares, one for each
Aggregator, each consisting of a seed.

The object `CorrectionWords` carries one correction word per tree level plus two
additional correction words for the leaf level, each playing a different role in
making the two Aggregators' otherwise-independent seed trees agree at every node
off the path to `leaf_index`:

- An **Internal Correction Word** (one per level) carries a single seed
  correction word, applied identically to both children's expanded seeds, and
  two separate control bit correction words, `ctrl_bit_left` and
  `ctrl_bit_right`, one per child. The construction of these seeds and control
  bits maintains the following invariant at each node: the two Aggregators'
  seeds and control bits differ if and only if the node is on-path.  If an
  Aggregator's control bit for the node being expanded is nonzero, it applies
  the correction word for that level to the seeds and control bits of the node's
  two children ({{vdpf-aux}}, `eval_next_children()`). At an off-path node the
  two control bits are equal, so both Aggregators apply the correction or
  neither does, and their seeds and control bits stay equal in every off-path
  descendant. At an on-path node the two control bits differ, so exactly one
  Aggregator applies the correction. The correction words are chosen so that the
  off-path child ends up with equal seeds and control bits for both Aggregators,
  while the on-path child keeps differing seeds and control bits.

- The **Leaf Correction Word** is a vector of `leaf_size` field elements. Added
  into a leaf's field elements by whichever Aggregator has that leaf's control
  bit set ({{vdpf-aux}}, `eval_all()`), it cancels out (both Aggregators apply
  it, or neither does) at every leaf other than `leaf_index`, and makes the two
  Aggregators' shares of the leaf at `leaf_index` sum to `values`.

- The **Proof Correction Word** does the analogous thing for the leaf-level
  sparsity proof ({{node-identity}}): it makes the two Aggregators' proof shares
  combine to the same value at every leaf except `leaf_index`, which is what
  lets {{verification}} check one-block-sparsity without revealing `leaf_index`.

The wire-format encoding of these types is given in {{msg-public-share}}.

~~~ python
class InternalCorrectionWord:
    def __init__(self, seed_cw: bytes, ctrl_bit_left: bool,
                 ctrl_bit_right: bool):
        self.seed_cw = seed_cw
        self.ctrl_bit_left = ctrl_bit_left
        self.ctrl_bit_right = ctrl_bit_right

LeafCorrectionWord: TypeAlias = list[F]
ProofCorrectionWord: TypeAlias = bytes

class CorrectionWords(Generic[F]):
    def __init__(self,
                 internal_cws: list[InternalCorrectionWord],
                 leaf_cw: LeafCorrectionWord,
                 proof_cw: ProofCorrectionWord):
        self.internal_cws = internal_cws
        self.leaf_cw = leaf_cw
        self.proof_cw = proof_cw
~~~

The algorithm invokes the auxiliary functions `extend()` and
`compute_leaf_level()`, defined in {{vdpf-aux}}. It walks the tree from the root
toward `leaf_index`, maintaining the same seed/control-bit invariant as Mastic's
own key generation ({{Section 3.1 of Mastic}}, informally): at every level,
exactly one of the two children the Client is *not* traveling toward gets a
correction word that, when applied by exactly one Aggregator, makes both
Aggregators' seeds and control bits agree off the path and disagree on the path.

~~~ python
def gen(self,
        leaf_index: int,
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
    # Step 2: Signal for each aggregator whether to apply correction
    # words.
    # We maintain the invariant such that:
    # - If a node is on path, ctrl[0] ^ ctrl[1] = 1.
    # - If a node is off path, ctrl[0] ^ ctrl[1] = 0.
    # Initially set the helper's index to be True, so helper applies
    # the correction word.
    ctrl_bits_initial = [False, True]
    # Compute the internal-level correction words sent to both
    # aggregators.
    internal_cws: list[InternalCorrectionWord] = []
    # Step 3: Loop through each internal level of the DPF tree.
    for i in range(self.depth):
        bit = bool((leaf_index >> (self.depth - 1 - i)) & 1)

        # Step 4: Expand PRG into seed and control bit for both
        # aggregators.
        (s0, t0) = self.extend(seeds[0], ctx, nonce)
        (s1, t1) = self.extend(seeds[1], ctx, nonce)

        # Steps 5 and 6: If the current level is a 1, we will
        # traverse the right child (`keep` set to 1).
        # Otherwise, traverse the left child (`keep` set to 0).
        (keep, lose) = (1, 0) if bit else (0, 1)

        # Steps 7, 8, 9: Compute the correction words for this
        # level's seed and control bit. Our goal is to maintain the
        # following invariant, after correction:
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
            InternalCorrectionWord(
                seed_cw, ctrl_bits[0], ctrl_bits[1]))

    # Sample leader and helper's random field elements and also the
    # proofs for block sparsity from their seeds at the leaf level.
    # During generation, we use the full path which is leaf_index
    # (the block index).
    leaf_index_bytes = leaf_index.to_bytes(
        (self.depth + 7) // 8, byteorder='big')
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
~~~

## Key Evaluation {#vdpf-key-eval}

The key evaluation algorithm is run independently by each Aggregator. Its inputs
are the report `nonce`, the Aggregator's ID (`0` for the first, `1` for the
second), the Aggregator's key (one of the two seeds output by `gen()`), the
Aggregator's initial control bit (`0` for one Aggregator, `1` for the other),
and the public share (consisting of the leaf correction word, proof correction
word, and internal correction words and control bits). Its outputs are the
Aggregator's share of every coordinate of the shared vector `F`, and one
sparsity proof for the leaf.

~~~ python
def eval_all(self,
             ctx: bytes,
             nonce: bytes,
             agg_id: int,
             initial_seed: bytes,
             initial_ctrl_bit: bool,
             cws: CorrectionWords[F],
             ) -> tuple[list[F], list[bytes]]:
    '''
    Evaluate the field elements expanded from the leaf nodes. Every
    leaf contributes its full `leaf_size` field elements, so the
    result has exactly `num_leaf_nodes * leaf_size` field elements.
    '''
    root_node = EvalNode(level=0, seed=initial_seed,
                         ctrl_bit=initial_ctrl_bit)
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
~~~

## Node Identity and the Leaf-Level Sparsity Proof {#node-identity}

Every leaf node's field elements and sparsity proof are sampled from an XOF
whose binder is `nonce + leaf_index_bytes`, that is, the report nonce
concatenated with the *encoding of that specific leaf's own index*
(`compute_leaf_level()`, {{vdpf-aux}}). This binds each leaf's output to its
identity within the tree. The concatenated sparsity proofs are hashed into a
one-hot check value, see ({{verification}}) for more details.

## Auxiliary Functions {#vdpf-aux}

~~~ python
class EvalNode:
    def __init__(self, level: int, seed: bytes, ctrl_bit: bool,
                leaf_index: int = 0):
        self.level = level
        self.seed = seed
        self.ctrl_bit = ctrl_bit
        self.leaf_index = leaf_index

def eval_next_children(self,
                       ctx: bytes,
                       nonce: bytes,
                       node: EvalNode,
                       internal_cw_list:
                           list[InternalCorrectionWord],
                       ) -> tuple[EvalNode, EvalNode]:
    seed_cw = internal_cw_list[node.level].seed_cw
    ctrl_left_cw = internal_cw_list[node.level].ctrl_bit_left
    ctrl_right_cw = internal_cw_list[node.level].ctrl_bit_right
    (s, t) = self.extend(node.seed, ctx, nonce)
    if node.ctrl_bit:
        s[0] = xor(s[0], seed_cw)
        t[0] ^= ctrl_left_cw
        s[1] = xor(s[1], seed_cw)
        t[1] ^= ctrl_right_cw
    left_child = EvalNode(level=node.level + 1, seed=s[0],
                          ctrl_bit=t[0],
                          leaf_index=node.leaf_index << 1)
    right_child = EvalNode(level=node.level + 1, seed=s[1],
                           ctrl_bit=t[1],
                           leaf_index=(node.leaf_index << 1) | 1)
    return (left_child, right_child)
~~~

~~~ python
def extend(self,
           seed: bytes,
           ctx: bytes,
           nonce: bytes,
           ) -> tuple[list[bytes], list[bool]]:
    '''
    Extend a seed into the seed and control bits for its left and
    right children in the tree.
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
    '''
    Compute the field elements and sparsity proof at a leaf node,
    expanded from the seed. `nonce` is the report nonce concatenated
    with the leaf's identity; see {{node-identity}}.
    '''
    xof = self.xof(
        seed, dst_alg(USAGE_CONVERT, self.algorithm_id, ctx), nonce)
    vals: list[F] = xof.next_vec(self.field, self.leaf_size)
    proof: bytes = xof.next(PROOF_SIZE)
    return (vals, proof)
~~~

# Specification of PREAMBLE {#vdaf}

As stated previously, an instance of PREAMBLE is determined by a `dimension`, a
`block_size`, and a validity circuit `valid: Valid[FLPMeasurement, FLPResult,
F]` that checks the contents of the one nonzero block: an `FLPMeasurement`,
which the circuit encodes into `flp.MEAS_LEN` field elements. PREAMBLE wraps the
circuit in Prio3's FLP construction ({{VDAF}}, based on {{BBCGGI19}}),
`flp = FlpBBCGGI19(valid)`.
PREAMBLE's Client measurement type is:

~~~ python
PreambleMeasurement: TypeAlias = tuple[
    tuple[bool, ...], FLPMeasurement]
~~~

A `PreambleMeasurement` is a `(block_index, block_content)` pair ({{overview}}):
`block_index` is the path (as a tuple of booleans, most significant bit first)
to the vector's one nonzero block, and `block_content` is that block's instance
of an `FLPMeasurement`. The chosen `flp` MUST accept a `block_size`-coordinate
block as its measurement; how `FLPMeasurement` is shaped, and hence how
`block_size` relates to `flp.MEAS_LEN` and `flp.OUTPUT_LEN`, is circuit-specific
and is fixed by each variant in {{variants}}. For a circuit that takes a
`length` parameter, such as `SumVec` or `MultihotCountVec` ({{Section 7.4 of
VDAF}}), `block_size` is that `length`.

The aggregate result has type `list[FLPResult]`, where `FLPResult` is likewise
a type defined by the validity circuit of the underlying FLP: one `FLPResult`
per block, in block order. The size of this list is equal to `num_leaf_nodes`.

The VDPF is instantiated over the same `field` as `FLP` with `num_leaf_nodes =
dimension / block_size` leaves and `leaf_size = flp.MEAS_LEN` field elements per
leaf, because the values it shares are the *encoded* block contents. This
instance of the VDPF is denoted `vdpf`. The length of an aggregate share
({{aggregation}}) is

~~~ python
output_len = num_leaf_nodes * flp.OUTPUT_LEN
~~~

because each block contributes the `flp.OUTPUT_LEN` field elements its encoded
form truncates to.

The XOF type in use is denoted `xof` ({{variants}} fixes a concrete choice).

## Fully Linear Proof {#flp}

PREAMBLE checks the contents of the nonzero block with a Fully Linear Proof
(FLP) system `flp`, which is a parameter of the construction.  PREAMBLE uses
`flp` only through the FLP interface of {{Section 7.1 of VDAF}}:

| Functionality        | Type            | Definition    |
|:---------------------|:----------------|:--------------|
| `flp.field`          | Attribute       | Section 7.1   |
| `flp.MEAS_LEN`       | Attribute       | Section 7.1   |
| `flp.OUTPUT_LEN`     | Attribute       | Section 7.1   |
| `flp.PROOF_LEN`      | Attribute       | Section 7.1   |
| `flp.VERIFIER_LEN`   | Attribute       | Section 7.1   |
| `flp.PROVE_RAND_LEN` | Attribute       | Section 7.1   |
| `flp.QUERY_RAND_LEN` | Attribute       | Section 7.1   |
| `flp.JOINT_RAND_LEN` | Attribute       | Section 7.1   |
| `flp.prove`          | Instance Method | Section 7.1   |
| `flp.query`          | Instance Method | Section 7.1   |
| `flp.decide`         | Instance Method | Section 7.1   |
| `flp.encode`         | Instance Method | Section 7.1.1 |
| `flp.truncate`       | Instance Method | Section 7.1.1 |
| `flp.decode`         | Instance Method | Section 7.1.1 |
{: #flp-functionalities title="FLP functionalities"}

In addition to implementing that interface, an FLP used with PREAMBLE MUST
satisfy the following:

1. `flp.field` is the field over which the VDPF is instantiated ({{vdaf}}). The
   VDPF secret-shares the encoded block, and each Aggregator queries the proof
   directly on its share of it.

1. `flp.truncate` is linear. Each Aggregator applies it to its share of every
   block, including the blocks whose shares sum to zero, and sums the results
   into its output share ({{verification}}). Prio3 relies on the same property
   when it truncates a measurement share ({{Section 7.2.2 of VDAF}}).

The FLP specified in {{Section 7.3 of VDAF}}, `FlpBBCGGI19`, implements this
interface for any validity circuit, so the requirements above restrict only the
choice of circuit. {{variants}} fixes the circuits for which this document
defines a PREAMBLE instantiation.

The field `flp.JOINT_RAND_LEN` MAY be zero, as for a circuit such as Count that
uses no joint randomness. As in Prio3 ({{Section 7.2.1 of VDAF}}), PREAMBLE then
omits the joint randomness machinery altogether: the Clients derive no blinds,
the Aggregators derive no joint randomness parts, and there is no joint
randomness seed to cross-check. The proof is unaffected. It is still generated,
secret-shared, and checked with `flp.decide()`, and `flp.prove()` and
`flp.query()` are invoked with an empty joint randomness. Everything in this
document that concerns joint randomness applies only when `flp.JOINT_RAND_LEN >
0`, and {{sharding}}, {{verification}}, and {{msg-serialization}} say what
changes otherwise.

> TODO When `flp.JOINT_RAND_LEN > 0`, each part binds the nonce, the encoded
> public share, and the VDPF seed. The public share and the VDPF seed determine
> the Aggregator's share, so they take the place of the measurement share that
> Prio3's and Mastic's parts bind alongside the nonce. This document does not
> prove that binding them is equivalent, that is, that a Client cannot choose
> its shares after seeing the joint randomness.

PREAMBLE's implementation of the VDAF interface ({{Section 5 of VDAF}}) is
specified in the following sections.

## Sharding {#sharding}

The sharding algorithm takes the measurement, the report `nonce`, and sharding
randomness of length `RAND_SIZE`, defined below. Its output is a public share,
`PreamblePublicShare`, and a pair of input shares, `PreambleInputShare`, one for
the *Leader* (Aggregator `0`) and one for the *Helper* (Aggregator `1`).

The sharding randomness is consumed as the VDPF's `RAND_SIZE` bytes (one
initial seed per Aggregator; {{vdpf-params}}), followed by four more seeds: the
Helper's proof-share seed, one joint-randomness blind per Aggregator, and one
prove-randomness seed. If `flp.JOINT_RAND_LEN == 0`, the two blinds are omitted,
leaving two more seeds. There is no measurement-share seed, because the FLP's
encoded measurement is exactly the VDPF block, which the VDPF already
secret-shares; the only secret a Client shares explicitly is the proof.

~~~ python
RAND_SIZE = (self.vdpf.RAND_SIZE
             + (1 + self.SHARES + 1) * self.xof.SEED_SIZE)
             # if flp.JOINT_RAND_LEN > 0

RAND_SIZE = (self.vdpf.RAND_SIZE
             + (1 + 1) * self.xof.SEED_SIZE)
             # if flp.JOINT_RAND_LEN == 0
~~~

## Verification {#verification}

1. Evaluate the VDPF share ({{vdpf-key-eval}}) over all `num_leaf_nodes *
  leaf_size` coordinates to obtain the Aggregator's share of the encoded vector,
  along with one sparsity proof per leaf.  Derive a one-hot check value by
  hashing the concatenation of those proofs, in leaf order, under the shared
  `verify_key`. The two Aggregators' proofs agree at every leaf exactly when at
  most one leaf is on-path, so verification rejects the report unless the two
  check values are equal.

1. Sum the encoded vector share block-wise to obtain the Aggregator's share of
   `encoded_block`, the FLP-encoded measurement produced by `shard()`.
   Separately, apply `flp.truncate()` to each block of the encoded vector share;
   the concatenation of the results is the Aggregator's output share.

1. If `flp.JOINT_RAND_LEN > 0`, recompute the Aggregator's own joint-randomness
   part from its blind, the nonce, the encoded public share, and its VDPF seed,
   exactly as `shard()` did. Combine it with the peer's part supplied in the
   public share to derive the corrected joint-randomness seed, and expand that
   into the joint randomness.  The corrected seed is cross-checked against the
   verifier message in `verify_next()`, as in {{Section 7.2.2 of
   VDAF}}. Otherwise, there is no joint randomness, and the Aggregator uses an
   empty one in the next step.

1. For each of the `PROOFS` proofs, query the Aggregator's share of
   `encoded_block` and its share of that proof, obtaining a verifier share.

The Aggregators then exchange verifier shares, and
`verifier_shares_to_message()` rejects the report if the one-hot check values
differ or if `flp.decide()` fails on any combined verifier, and otherwise
outputs the joint-randomness seed derived from both Aggregators' parts as the
verifier message. If `flp.JOINT_RAND_LEN == 0`, there are no parts to combine,
and the verifier message is empty.

~~~ python
def verifier_shares_to_message(
        self,
        ctx: bytes,
        agg_param: None,
        verifier_shares: list[PreambleVerifierShare[F]],
        ) -> PreambleVerifierMessage:
    assert len(verifier_shares) == self.SHARES
    (share_0, share_1) = verifier_shares
    if share_0.one_hot_check != share_1.one_hot_check:
        raise ValueError("One-hot check failed")

    # Unshard the verifier shares into the verifier message.
    verifiers = vec_add(share_0.verifiers_share,
                        share_1.verifiers_share)

    # Verify that each proof is well-formed and the input is valid.
    for _ in range(self.PROOFS):
        (verifier, verifiers) = front(
            self.flp.VERIFIER_LEN, verifiers)
        if not self.flp.decide(verifier):
            raise ValueError(
                "Decision function failed after combining all "
                "verifier shares.")

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
~~~


## Validity of Aggregation Parameters {#agg-param-validity}

PREAMBLE does not use an aggregation parameter. Every input share MUST be used
only once:

~~~ python
def is_valid(self, agg_param, previous_agg_params):
    return len(previous_agg_params) == 0
~~~


## Aggregation {#aggregation}

An output share is this Aggregator's share of every block's aggregatable form:
`num_leaf_nodes` consecutive groups of `flp.OUTPUT_LEN` field elements in all
({{vdaf}}).

Aggregating a set of output shares sums them element-wise:

~~~ python
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
~~~


## Unsharding

To unshard, the Collector adds up the aggregate shares element-wise, then
decodes each block's `flp.OUTPUT_LEN` field elements with the circuit that
validated it, using the `blocks()` helper ({{aux}}) to split the flat aggregate
into one slice per block. The result is one `FLPResult` per block, in block
order:

~~~ python
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
~~~


## Message Serialization {#msg-serialization}

### Public Share {#msg-public-share}

The public share is the VDPF public share (`CorrectionWords`) output by key
generation ({{vdpf-key-gen}}), followed by the two Aggregators'
joint-randomness parts, which are absent if `flp.JOINT_RAND_LEN == 0`.  The
VDPF public share has `depth` internal correction words, a leaf correction word
of `flp.MEAS_LEN` field elements, and a leaf proof correction word. The control
bits are represented here as full bytes rather than bit-packed, matching this
document's reference implementation.

~~~
struct {
    uint8 seed_cw[KEY_SIZE];
    uint8 ctrl_bit_left;   /* MUST be 0 or 1 */
    uint8 ctrl_bit_right;  /* MUST be 0 or 1 */
} InternalCorrectionWord;

struct {
    InternalCorrectionWord internal_cws[depth];
    F leaf_cw[flp.MEAS_LEN];
    uint8 proof_cw[PROOF_SIZE];
} CorrectionWords;

struct {
    CorrectionWords cws;
    /* only if flp.JOINT_RAND_LEN > 0 */
    uint8 joint_rand_parts[2 * xof.SEED_SIZE];
} PreamblePublicShare;
~~~

The `CorrectionWords` are encoded and decoded as follows. `leaf_size` is
`flp.MEAS_LEN`, so `correction_words_size()` is the length of the encoded
`CorrectionWords`:

~~~ python
def encode_correction_words(self, cws: CorrectionWords[F]) -> bytes:
    result = bytes()
    for internal_cw in cws.internal_cws:
        result += internal_cw.seed_cw
        result += byte(internal_cw.ctrl_bit_left)
        result += byte(internal_cw.ctrl_bit_right)
    result += self.field.encode_vec(cws.leaf_cw)
    result += cws.proof_cw
    return result

def correction_words_size(self) -> int:
    return (self.depth * (self.KEY_SIZE + 2) +
            self.field.ENCODED_SIZE * self.leaf_size +
            PROOF_SIZE)

def decode_correction_words(
        self, encoded: bytes) -> CorrectionWords[F]:
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
~~~

### Input Share {#msg-input-share}

In both input shares, `joint_rand_blind` is absent if
`flp.JOINT_RAND_LEN == 0`.

The Leader's input share:

~~~
struct {
    uint8 vdpf_seed[KEY_SIZE];
    F proof_share[flp.PROOF_LEN * PROOFS];
    /* only if flp.JOINT_RAND_LEN > 0 */
    uint8 joint_rand_blind[xof.SEED_SIZE];
} PreambleLeaderShare;
~~~

The Helper's input share replaces the Leader's explicit `proof_share` vector
with a single seed, which the Helper expands using `helper_proof_share()`:

~~~
struct {
    uint8 vdpf_seed[KEY_SIZE];
    uint8 proof_share[xof.SEED_SIZE];
    /* only if flp.JOINT_RAND_LEN > 0 */
    uint8 joint_rand_blind[xof.SEED_SIZE];
} PreambleHelperShare;
~~~

### Verifier Share {#msg-verifier-share}

`joint_rand_part` is absent if `flp.JOINT_RAND_LEN == 0`.

~~~
struct {
    uint8 one_hot_check[PROOF_SIZE];
    F verifiers_share[flp.VERIFIER_LEN * PROOFS];
    /* only if flp.JOINT_RAND_LEN > 0 */
    uint8 joint_rand_part[xof.SEED_SIZE];
} PreambleVerifierShare;
~~~

### Verifier Message {#msg-verifier-message}

The verifier message is empty (zero bytes) if
`flp.JOINT_RAND_LEN == 0`.

~~~
/* only if flp.JOINT_RAND_LEN > 0 */
PreambleVerifierMessage = uint8[xof.SEED_SIZE]
~~~

### Aggregate Share and Output Share {#msg-agg-share}

Both the aggregate share and the output share are a flat vector of
`num_leaf_nodes * flp.OUTPUT_LEN`-many field elements:

~~~
agg_share = out_share = F[num_leaf_nodes * flp.OUTPUT_LEN];
~~~

## Auxiliary {#aux}

~~~python
def blocks(self, vec: list[F], block_len: int) -> list[list[F]]:
    """
    Split a flat vector into one slice per block of the vector
    space, in leaf order.

    Both vectors Preamble handles have this shape: the encoded one
    that `vdpf.eval_all()` returns (`block_len == vdpf.leaf_size`)
    and the truncated one that is aggregated (`block_len ==
    flp.OUTPUT_LEN`).  Neither is typed as `list[list[F]]`, because a
    flat vector is what the wire encoding and `vec_add` want -- an
    output share is summed across Clients element-wise, and its block
    boundaries carry no information the shape doesn't already fix. So
    the boundaries live here instead, in one place, rather than as
    index arithmetic at each use.

    """
    expected = self.vdpf.num_leaf_nodes * block_len
    if len(vec) != expected:
        raise ValueError(
            f"expected {expected} field elements "
            f"({self.vdpf.num_leaf_nodes} blocks of {block_len}), "
            f"got {len(vec)}.")
    return [vec[i * block_len:(i + 1) * block_len]
            for i in range(self.vdpf.num_leaf_nodes)]
~~~

The joint randomness seed is derived from the Aggregators' parts as in Prio3
({{Section 7.2.6 of VDAF}}), except that the domain separation tag is built with
`dst_alg()` ({{dst}}):

~~~python
def joint_rand_seed(self,
                    ctx: bytes,
                    joint_rand_parts: list[bytes]) -> bytes:
    """Derive the joint randomness seed from its parts."""
    return self.xof.derive_seed(
        zeros(self.xof.SEED_SIZE),
        dst_alg(USAGE_JOINT_RAND_SEED, self.ID, ctx),
        concat(joint_rand_parts),
    )
~~~

## Variants {#variants}

This section defines four instantiations of PREAMBLE. Each fixes the validity
circuit wrapped by `flp` ({{flp}}) to one of the Prio3 circuits of {{Section 7.4
of VDAF}} or, for PreambleL1BoundSum, to the circuit of {{Prio3L1BoundSum}}, and
the XOF to `XofTurboShake128` ({{Section 6.2.1 of VDAF}}). In
PreambleMultihotCountVec, PreambleSumVec and PreambleL1BoundSum, `block_size` is
the circuit's `length` parameter: the number of entries in the block content a
Client submits, not the number of field elements that content encodes to. In
PreambleCount, `block_size` is fixed to 1. Each instantiation has its own
algorithm identifier, which feeds every domain separation tag ({{dst}}),
including the VDPF's.

Like Prio3, each instantiation uses `Field128` and a single proof.


### PreambleCount {#preamble-count}

| Parameter | Value                                      |
|:----------|:-------------------------------------------|
| `ID`      | `0xFFFFFFFC`                               |
| `field`   | `Field128` ({{Section 6.1.4 of VDAF}})     |
| `Valid`   | `Count(field)` ({{Section 7.4.1 of VDAF}}) |
| `PROOFS`  | `1`                                        |
| `xof`     | `XofTurboShake128`                         |
{: title="Parameters for PreambleCount"}

`block_size` is fixed to 1, so it is not a parameter of this instantiation and
`dimension` is the number of blocks. The block content is a single integer, 0 or
1, as in Prio3Count, rather than a vector. The circuit encodes it as one field
element, so `flp.MEAS_LEN = 1`, and its truncation is the identity, so
`flp.OUTPUT_LEN = 1`. The aggregate result is one `int` per block: the number of
Clients that submitted a 1 for that block.

This is the only instantiation with `flp.JOINT_RAND_LEN == 0`, so it has no
joint randomness parts, and its verifier message is empty ({{flp}}).

### PreambleMultihotCountVec {#preamble-multihot-count-vec}

| Parameter | Value                                                                                       |
|:----------|:--------------------------------------------------------------------------------------------|
| `ID`      | `0xFFFFFFFE`                                                                                |
| `field`   | `Field128` ({{Section 6.1.4 of VDAF}})                                                      |
| `Valid`   | `MultihotCountVec(field, block_size, max_weight, chunk_length)` ({{Section 7.4.5 of VDAF}}) |
| `PROOFS`  | `1`                                                                                         |
| `xof`     | `XofTurboShake128`                                                                          |
{: title="Parameters for PreambleMultihotCountVec"}

The block content is a vector of `block_size` Boolean values of which at most
`max_weight` are `True`, as in Prio3MultihotCountVec, and `0 < max_weight <=
block_size`. The circuit encodes it as the `block_size` counters followed by
`max_weight.bit_length()` bits of reported weight, so `flp.MEAS_LEN =
block_size + max_weight.bit_length()`, and truncates the encoding to the
counters, so `flp.OUTPUT_LEN = block_size`. The aggregate result is one
`list[int]` of `block_size` counts per block.

### PreambleSumVec {#preamble-sum-vec}

| Parameter | Value                                                                             |
|:----------|:----------------------------------------------------------------------------------|
| `ID`      | `0xFFFFFFFD`                                                                      |
| `field`   | `Field128` ({{Section 6.1.4 of VDAF}})                                            |
| `Valid`   | `SumVec(field, block_size, 2^bits - 1, chunk_length)` ({{Section 7.4.3 of VDAF}}) |
| `PROOFS`  | `1`                                                                               |
| `xof`     | `XofTurboShake128`                                                                |
{: title="Parameters for PreambleSumVec"}

The block content is a vector of `block_size` integers, each in the range `[0,
2^bits)`, as in Prio3SumVec, so the circuit's `max_measurement` is `2^bits - 1`.
The circuit encodes each integer as `bits` field elements, so `flp.MEAS_LEN =
block_size * bits`, and truncates the encoding by recombining those bits, so
`flp.OUTPUT_LEN = block_size`. The aggregate result is one `list[int]` of
`block_size` sums per block. As in Prio3SumVec, it is RECOMMENDED to set
`chunk_length` to an integer near the square root of `flp.MEAS_LEN` ({{Section
7.4.3.1 of VDAF}}).

### PreambleL1BoundSum {#preamble-l1-bound-sum}

| Parameter | Value                                                                          |
|:----------|:-------------------------------------------------------------------------------|
| `ID`      | `0xFFFFFFFB`                                                                   |
| `field`   | `Field128` ({{Section 6.1.4 of VDAF}})                                         |
| `Valid`   | `L1BoundSum(field, block_size, max_value, chunk_length)` ({{Prio3L1BoundSum}}) |
| `PROOFS`  | `1`                                                                            |
| `xof`     | `XofTurboShake128`                                                             |
{: title="Parameters for PreambleL1BoundSum"}

The block content is a vector of `block_size` integers, each in the range `[0,
max_value]`, whose sum is also at most `max_value`, as in Prio3L1BoundSum. The
bound is on the block's L1 norm, not on each coordinate independently, which
distinguishes this instantiation from PreambleSumVec. The circuit is defined in
{{Prio3L1BoundSum}} and is not repeated here. With `bits =
max_value.bit_length()`, it encodes each integer as `bits` field elements,
followed by `bits` field elements for the bit-decomposed claimed sum, which the
circuit checks against the coordinates. So `flp.MEAS_LEN = (block_size + 1) *
bits`.  The truncation drops the claimed sum, so `flp.OUTPUT_LEN = block_size`:
the VDPF carries the claimed sum, but it is not aggregated. The aggregate
result is one `list[int]` of `block_size` sums per block. As in PreambleSumVec,
it is RECOMMENDED to set `chunk_length` to an integer near the square root of
`flp.MEAS_LEN`.


# Security Considerations {#security-considerations}

> TODO

# IANA Considerations {#iana-considerations}

IANA is requested to add new identifiers to the "VDAF Identifiers" registry,
under the "Verifiable Distributed Aggregation Functions (VDAF)" heading, which
is described in {{Section 10 of VDAF}}. The new entries are as follows:

| Value        | Scheme                   | Type | Reference                |
|:-------------|:-------------------------|:-----|:-------------------------|
| `0xFFFFFFFE` | PreambleMultihotCountVec | VDAF | {{variants}} of RFC XXXX |
| `0xFFFFFFFD` | PreambleSumVec           | VDAF | {{variants}} of RFC XXXX |
| `0xFFFFFFFC` | PreambleCount            | VDAF | {{variants}} of RFC XXXX |
| `0xFFFFFFFB` | PreambleL1BoundSum       | VDAF | {{variants}} of RFC XXXX |
{: #codepoints title="Additional entries for the VDAF Identifiers registry"}

> TODO The codepoints in this section are from the private codepoint range and
> are used for testing purposes. We will update this table with the codepoints
> assigned by IANA.

(RFC EDITOR: Please replace "RFC XXXX" above with the RFC number assigned to
this document.)

--- back

# Acknowledgments
{:numbered="false"}

# Test Vectors
{:numbered="false"}

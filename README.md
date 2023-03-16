# halo2-base64

This circuit takes a string written in base64 (i.e. R0g=) and converts it to a ASCII char string (i.e. GH) and verifies that the conversion was done correctly. This is the halo2 circuit that corresponds to [this circom base64 decoding circuit](https://github.com/zk-email-verify/zk-email-verify/blob/main/circuits/base64.circom). The usage in zk-email will be analogous to [this line in the circom circuits](https://github.com/zk-email-verify/zk-email-verify/blob/solidity/circuits/email.circom#L115), where the body hash value in the DKIM header (i.e. bh=...) is converted to a format that matches what the sha256 circuit that hashes the email body actually outputs.

To run this repo, do

```
cargo build
cargo test -- --nocapture
```

## Circuit Layout

<img width="601" alt="image" src="https://i.imgur.com/ggNtJMP.png">

This circuit maps 4 6-bit values to 3 8-bit values. The way it works is via a bit decomposition into pairs of bits, which are then reassembled into the 8 bit values. All the intermediate values are looked up in the lookup tables of bit decomposition to ensure that the conversion was done correctly.

We are optimizing for simplicity and proving time, so we opted to use the first design. Note that we will wrap this proof into the rest of halo2 zk-email and then into axiom's recursive prover, so we are not concerned with verifier time or size. The second design can be more efficient verifier-wise however. It may also make sense to, instead of lookups, to range check each column and then define an arithmetic custom gate; due to rotations, we do not opt for this path.

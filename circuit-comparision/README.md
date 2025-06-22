Implementation of proof of merkle proof of inclusion implmented in Noir, Leo and Plonky3 for comparision.

## Noir

```
[circuit-comparision]$ cd noir_merkle_inclusion/
[noir_merkle_inclusion]$ time nargo test --show-output --format pretty
```

## ALeo
```
[circuit-comparision]$ cd leo_merkle/
[leo_merkle]$ time leo execute merkle_inclusion_verifier.aleo/verify_inclusion --print --file test_input_16.txt
```

## Plonky 3
```
[circuit-comparision]$ cd plonky3-merkle-tree/

[plonky3-merkle-tree]$ cargo run --release
```

## Comparision

|         | Proof Time | Proof Size (Bytes) |
|---------+------------+--------------------|
| Noir    |     0.143s |              14080 |
| Aleo    |     19.663 |                375 |
| Plonky3 |      0.063 |             215900 |
|         |            |                    |

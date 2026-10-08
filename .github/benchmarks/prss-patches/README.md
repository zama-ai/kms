# TEMP: REMOVE BEFORE MERGE — PRF block-store experiments

The preparation script applies these patches only to isolated benchmark sources. Production files in the checkout stay unchanged.

| Variant | Kernel | Input construction |
|---|---|---|
| `scalar` | #894 scalar | Original byte stores |
| `group2`, `group4`, `group8` | Batched | Original byte stores |
| `scalar-word` | #894 scalar | Safe `u128` construction and little-endian block assignment |
| `group8-word` | Eight counters | Safe `u128` construction and little-endian block assignment |
| `group16-word` | Sixteen counters | Same safe construction; 64 AES blocks per F4 group |
| `group8-neon` | Eight counters | Experimental unsafe NEON store on little-endian ARM with NEON enabled |
| `group8-acc`, `group16-acc` | Eight/sixteen counters, outputs added in place | Same safe construction as `-word`; checkout source |

The workflow selects the `full` comparison and measures every harness case, including masks and session construction.
Its variants are `main` at `d09406212`, `scalar` (#894 head `d4ec6790c`), and `group8-new`/`group16-new` from the checkout.
main uses the same harness with its older session constructor. The `main` comparison measures only `main` and `group16-new`. The `accumulate` comparison measured `group8-word` and `group16-word` from commit `3ea76bb44`, whose PRF groups
return arrays, against `group8-acc` and `group16-acc` from the checkout, which add each output to the caller's sums in place.
The `group16` comparison measures only `group8-word` against `group16-word`.
The local `refactor` comparison builds `group8-acc`/`group16-acc` from the uncommitted snapshot `192a80aef` against
`group8-new`/`group16-new` from the checkout. Current kernels take their group size from `PRF_COUNTER_GROUP`.
The preparation script's default `all` mode retains the complete control matrix. In that mode NEON is prepared only on ARM.
Neither safe assignment nor the variant name guarantees one machine store. Inspect the saved assembly.

The patches derive from the independent review in `artifacts/prss-review-store-forwarding-20261007/`.
They retain original byte-encoding comparisons for F3/F4/F8 and Z64/Z128, with separate psi/chi counter-limit cases.
These are equivalence tests, not frozen known-answer vectors. Existing group/kernel tests also run for each candidate.

Original scalar sources come from `d4ec6790c`; original grouped PRF writers come from `36bb8f3a7`.
Portable groups use the current checkout's PRF implementation, so the historical `group-word.patch` is not reapplied.
The group size changes only in the isolated kernel copies. The checkout remains on group eight.
All variants use the same harness, flags and dependencies and run sequentially on one host.
CI uses a separate Cargo target directory per variant to prevent stale cross-archive artifacts.
The unsafe patch is a disposable measurement reference, not a proposed production implementation.

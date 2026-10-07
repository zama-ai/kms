# TEMP: REMOVE BEFORE MERGE — PRF block-store experiments

The preparation script applies these patches only to isolated benchmark sources. Production files in the checkout stay unchanged.

| Variant | Kernel | Input construction |
|---|---|---|
| `scalar` | #894 scalar | Original byte stores |
| `group2`, `group4`, `group8` | Batched | Original byte stores |
| `scalar-word` | #894 scalar | Safe `u128` construction and little-endian block assignment |
| `group8-word` | Eight counters | Safe `u128` construction and little-endian block assignment |
| `group8-neon` | Eight counters | Experimental unsafe NEON store on little-endian ARM with NEON enabled |

The NEON variant is prepared only on ARM hosts. The x86 workflow records its exclusion and measures the safe path explicitly.
Neither safe assignment nor the variant name guarantees one machine store. Inspect the saved assembly.

The patches derive from the independent review in `artifacts/prss-review-store-forwarding-20261007/`.
They retain original byte-encoding comparisons for F3/F4/F8 and Z64/Z128, with separate psi/chi counter-limit cases.
These are equivalence tests, not frozen known-answer vectors. Existing group/kernel tests also run for each candidate.

Original scalar sources come from `d4ec6790c`; original grouped sources come from the checkout. No original PRF writer is
replaced in those controls. All variants use the same harness, flags and dependencies and run sequentially on one host.
CI uses a separate Cargo target directory per variant to prevent stale cross-archive artifacts.
The unsafe patch is a disposable measurement reference, not a proposed production implementation.

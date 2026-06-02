# tfhe-fft-repro

Minimal standalone crate that reproduces the **codegen-time blowup** in
`tfhe-fft 0.10.1` between rustc 1.94 and 1.96, isolated from the kms workspace.

Observed in `cargo --timings` (kms build, Linux/x86_64):

| phase            | 1.94  | 1.96   |
|------------------|-------|--------|
| tfhe-fft frontend| 1.7s  | 1.6s   |
| tfhe-fft codegen | 201s  | 9235s  | ← ~46× — pure LLVM/codegen blowup

**x86_64 only.** The blowup is in the AVX-512 path (`tfhe-fft` `avx512` feature →
`pulp/x86-v4`). On aarch64 that path compiles to scalar no-ops, so it can't be
reproduced on macOS/ARM or Linux/ARM. 1.96 also bumped the minimum LLVM to 21 — a
prime suspect for an AVX-512 codegen cliff.

## Quick start

```bash
# Cold build, see how long tfhe-fft's codegen takes on the active toolchain.
cargo clean && cargo build --timings
#   -> opens target/cargo-timings/cargo-timing.html ; look at the tfhe-fft bar.

# Just build tfhe-fft (and its deps), nothing else.
cargo build -p tfhe-fft

# Compare toolchains (install with: rustup toolchain install nightly-YYYY-MM-DD)
cargo clean && time cargo +1.94.0 build -p tfhe-fft
cargo clean && time cargo +1.96.0 build -p tfhe-fft
```

## Confirm it's the AVX-512 path

Turn `avx512` off and the codegen time should collapse back to "fast":

```bash
# default-features=false drops std+avx512; re-add std (+fft128/serde) without avx512.
cargo clean && time cargo build -p tfhe-fft \
  --no-default-features --features std,fft128,serde
```

If that's fast on 1.96 while the default build is slow, the regression is in the
AVX-512 codegen, as expected.

## Digging into the codegen

```bash
# Which monomorphizations dominate LLVM IR (needs: cargo install cargo-llvm-lines)
cargo +nightly llvm-lines -p tfhe-fft | head -40

# Per-pass LLVM timing — shows whether a single pass (e.g. an opt/vectorizer pass)
# is the one that exploded.
RUSTFLAGS="-Cllvm-args=-time-passes" cargo build -p tfhe-fft 2>llvm-passes.txt

# rustc self-profile (frontend vs codegen breakdown, per query).
RUSTFLAGS="-Zself-profile" cargo +nightly build -p tfhe-fft
#   -> analyze the .mm_profdata with `summarize` / `crox` (measureme tools).

# Sweep codegen-units to see if the blowup is per-CGU size sensitive.
for n in 1 16 256; do
  cargo clean
  echo "== codegen-units=$n =="
  time RUSTFLAGS="-Ccodegen-units=$n" cargo build -p tfhe-fft
done
```

## Notes / knobs

- **Features**: edit `Cargo.toml`'s `tfhe-fft` line. The kms-resolved set is
  `[avx512, default, fft128, serde, std]`; `default` already pulls `std + avx512`.
- **Profile**: deps build at `opt-level = 3, codegen-units = 16` (matching kms),
  no LTO. The blowup is in per-CGU codegen, so LTO isn't needed to see it.
- **Portable**: empty `[workspace]`, no `rust-toolchain`, no `[patch]`. `tar czf
  tfhe-fft-repro.tgz tfhe-fft-repro/` and drop it on any Linux/x86 box.
- This crate is untracked in the kms repo — it won't end up in a PR.

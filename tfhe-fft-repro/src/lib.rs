// Intentionally (almost) empty. The point of this crate is to make a plain
// `cargo build` compile tfhe-fft as a dependency at opt-level 3 / codegen-units 16,
// which reproduces the codegen-time blowup. A declared dependency is compiled in
// full (frontend + codegen) regardless of whether anything here uses it, so we
// don't need to call into it to trigger the slow codegen.
//
// If you want to also exercise it at runtime (e.g. for profiling or to confirm
// behaviour, not just compile time), drop a small example under `examples/` — see
// README.md for an API sketch.

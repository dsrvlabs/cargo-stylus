# Optimizing Stylus Program WASM Binaries

WASM programs need to be small to be deployed onchain. Stylus applies [brotli compression](https://github.com/google/brotli), which empirically reduces the footprint of common Rust WASMs by over 50%, the Stylus runtime obeys the EVM contract size limit of 24KB. This means that, after compression, **all WASMs must not exceed 24KB**.

On modern platforms, tools like `cargo` don’t have to worry about the size of the binaries they produce. This is because there’s many orders of magnitude more storage available than even the largest of binaries, and for most applications it’s media like images and videos that constitutes the majority of the footprint.

Nevertheless, systems programming languages compete for viability in the OS and embedded space, where resource constraints are extremely strict. Hence, while not the default options, tooling often provides mechanisms for reducing binary bloat. This document seeks to explain these options so that Stylus programmers can write apps that are affordable to deploy.

## Compiler Flags

The Rust compiler supports various config options for shrinking binary sizes.

### `Cargo.toml`

```toml
[profile.release]
codegen-units = 1        # prefer efficiency to compile time
panic = "abort"          # use simple panics
opt-level = "z"          # optimize for size ("s" may also work)
strip = true             # remove debug info
lto = true               # link time optimization
debug = false            # no debug data
rpath = false            # no run-time search path
debug-assertions = false # prune debug assertions
incremental = false      # no incremental builds
```

### `.cargo/config.toml`

```toml
[build]
target = "wasm32-unknown-unknown"

[target.wasm32-unknown-unknown]
rustflags = [
  "-C", "link-arg=-zstack-size=8192", # shrink the heap
]
```

### `nightly flags`

Additional unstable nightly flags may help too.

```bash
cargo +nightly build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort
```

The above configures the standard library to not include panic strings, which are useless on chain but may take up considerable space.

```bash
cargo stylus check | deploy --nightly
```

## Other Tooling

Additional wasm-specific tooling exists to shrink binaries. Due to being 3rd party, users should use these at their own risk.

### `wasm-opt`

[wasm-opt](https://docs.rs/wasm-opt/0.113.0/wasm_opt/) applies techniques to further reduce binary size, usually netting around 10%.

```bash
cargo stylus check | deploy --wasm-opt
```
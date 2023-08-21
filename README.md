# cargo-libafl

**This repository is outdated. It is superseded by [libafl_libfuzzer](https://github.com/AFLplusplus/LibAFL/pull/981)!**

This cargo utility is a replacement for (and a fork of) [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) to use a LibAFL-based fuzzer instead of libfuzzer.

The available features are still behind the original cargo-fuzz.

## Install

You need a nightly compiler to use cargo-libafl.

```
cargo install -f cargo-libafl 
```

## Use

```
cargo libafl --help
```

### Custom Runtimes

If you need to use a custom runtime for your target, e.g. when using custom mutators, define an environmental variable `CUSTOM_LIBAFL_RUNTIME` to the target/release folder of your runtime. Note that your runtime should match the name (`cargo-libafl-runtime`) and the flags of the original runtime. To do this effectively, you should copy the `cargo-libafl-runtime` folder and modify it to your needs.

#### License

<sup>
Licensed under either of <a href="LICENSE-APACHE">Apache License, Version
2.0</a> or <a href="LICENSE-MIT">MIT license</a> at your option.
</sup>

<br>

<sub>
Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in this crate by you, as defined in the Apache-2.0 license, shall
be dual licensed as above, without any additional terms or conditions.
</sub>

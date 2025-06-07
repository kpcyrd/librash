# librash

Rust system library for cryptographic hashes.

This library provides two interfaces into the C dynamic linking ecosystem:

- A binary interface that can be accessed through a (dynamic-)linker
- A macro based API drop-in that redirects `EVP_*` function calls

Due to this design, it's possible to select this as an OpenSSL drop-in at
compile-time, but the compiled binary can still co-exist with other programs
that depend on an actual OpenSSL `libcrypto.so` to be present. You could even
load both into the same process without having conflicting symbols.

## Build instructions

```
cargo cbuild --release
## optional
#cargo ctest
cargo cinstall --release --frozen --prefix /usr --destdir /tmp/some-place
```

## License

`MIT OR Apache-2.0`

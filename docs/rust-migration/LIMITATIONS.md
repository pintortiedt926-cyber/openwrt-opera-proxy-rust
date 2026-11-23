# Limitations, Security Audit & Known Deviations

## 1. Intentional Security Deviation: Strict TLS Verification on `api2.sec-tunnel.com`

- **Upstream Go behavior (`main.go:554-557`, `911-914`)**: Go connects to `api2.sec-tunnel.com` with `ServerName: args.fakeSNI` (empty string by default = no SNI) and `InsecureSkipVerify: true`. Empirically, Opera's `api2.sec-tunnel.com` returns a valid Let's Encrypt certificate (`CN=sec-tunnel.com`, SAN `api2.sec-tunnel.com`) when SNI is `api2.sec-tunnel.com`, and returns a self-signed fallback certificate (`CN=h05-22-01.best.am4.osa`) when SNI is omitted or replaced with a fake SNI.
- **Safe Rust behavior**: Per project security policy, certificate verification is **never disabled** anywhere in the Rust port:
  - **Proxy nodes (`*.sec-tunnel.com`)**: Send `fake-SNI` (or omit SNI when `-fake-SNI` is empty) while **strictly verifying** the peer certificate chain and hostname against the real proxy hostname (`entry.Host` or `<cc>0.sec-tunnel.com`) using `webpki-roots` or `-cafile`. This works on live Opera nodes and is verified in automated tests.
  - **SurfEasy API (`api2.sec-tunnel.com`)**: By default (`-fake-SNI ""`), sends SNI `api2.sec-tunnel.com` and strictly verifies the certificate against `api2.sec-tunnel.com` + `RootCertStore`. If a user sets `-fake-SNI <other-host>`, the Rust port still strictly verifies the API server certificate against `api2.sec-tunnel.com`, which will fail against Opera's live API server if Opera serves its self-signed fallback cert for non-matching SNI. Users in SNI-censored networks who need to reach `api2.sec-tunnel.com` without real SNI can use `-api-proxy`, `-api-proxy-file`, `-discover-csv`, or retain the Go fallback.

## 2. Packaging & Verification Scope

- **OpenWrt 23.05 / 24.10 / 25.12 (`aarch64_cortex-a53` & `mipsel_24kc`)**:
  - `aarch64_cortex-a53`: Live-installed and verified end-to-end (`opkg install`, `procd`, `luci-app-opera-proxy` RPC, HTTP + SOCKS5 live Opera VPN, 2.0–2.3 MiB RSS) on real GL.iNet MT6000 OpenWrt 24.10.1; OpenWrt 25.12 `.apk` verified with real `apk-tools 3.0.5`.
  - `mipsel_24kc` (`ramips/mt7621`): Because `ring` does not support 32-bit MIPS, `mipsel_24kc` builds with `--no-default-features --features pure-rust-crypto` (`rustls-rustcrypto`, 100% pure Rust TLS 1.2/1.3) and Rust Tier 3 `-Z build-std=core,alloc,std,panic_abort`. The resulting ELF32 LE binary is statically linked with musl and verified to use `MIPS32r2` `fp_abi=3 (SOFT)` (`ases=0x0`, no hardware FPU instructions). All 39 automated tests pass under `pure-rust-crypto`; on-device execution on an actual MT7621 router has not yet been run (only MT6000 ARM64 was available).
- **Docker / OpenWrt SDK locally**: On the Windows build host, `com.docker.service` requires Administrator privileges to start, so local ARM64/MIPSEL cross-compilation used `rustc` + `zig cc` (`aarch64-linux-musl` / `mipsel-linux-musleabi -mcpu=mips32r2+soft_float`). Official OpenWrt 23.05, 24.10, and 25.12 SDK builds for both `mediatek/filogic` and `ramips/mt7621` are wired into the test-only GitHub Actions workflow `.github/workflows/rust-test.yml`.

## 3. Upstream Go Notes

- At pinned SHA `41ae319812170ca1bcbc7e4e35ada2aad46509ea`, upstream `handler/bypass_test.go` fails `go test ./handler/...` due to a stale 3-argument call to `NewProxyHandler` (fixed in Rust test suite).

## 4. Safe Rust & Dependency Security Inventory

- Crate sources (`src/` and `tests/`): `#![forbid(unsafe_code)]` enforced at crate root (zero `unsafe` in our code).
- No C FFI bindings to glibc or OpenSSL. Binary is 100% statically linked with musl libc.
- Security-sensitive third-party crates (locked in `Cargo.lock`):
  - `rustls 0.23.46` / `tokio-rustls 0.26.6` / `rustls-webpki 0.103.17` / `webpki-roots 1.0.12` — TLS 1.2/1.3 and Mozilla root trust anchors.
  - `ring 0.17.14` — audited cryptography primitives (contains internal C/assembly for constant-time primitives and ARMv8 acceleration).
  - `hyper 1.12.0` / `hyper-util 0.1.21` / `h2 0.4.20` — HTTP/1.1 & HTTP/2 protocol framing.
  - `tokio 1.54.1` — async I/O runtime.
  - `sha1 0.10.7` / `sha2 0.10.9` / `md-5 0.10.6` — RustCrypto digests (required by SurfEasy SHA1 hashes and HTTP Digest Auth).
  - `getrandom 0.2.17` — OS CSPRNG (`getrandom(2)` on Linux).

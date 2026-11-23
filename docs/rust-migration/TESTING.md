# Testing Report — Opera Proxy Safe Rust Port

## Pinned Sources

- Upstream Go: `Alexey71/opera-proxy` @ `41ae319812170ca1bcbc7e4e35ada2aad46509ea` (`v1.32.0`)
- Packaging / LuCI: `recrumptor/openwrt-opera-proxy-bin` @ `81cef91cf647c8bc148f65532fc8746670f45bf9`

---

## 1. Upstream Go Baseline Tests

Working directory: `upstream-go/` (Go `1.27.4`):

- `go test -v . ./dialer/... ./seclient/... ./resolver/... ./clock/... ./log/...` → **PASS** (`TestLoadProxyBypassList`, `TestBypassDialerRoutesByHostPattern`, `TestNewBypassDialerRejectsInvalidPattern`).
- `go test ./handler/...` → **FAIL (upstream bug)**: `handler/bypass_test.go` lines 44 & 69 call `NewProxyHandler` with 3 arguments while `handler/handler.go` defines 2 arguments.
- Reference binaries built:
  - `upstream-go/bin/opera-proxy-ref.exe` (8,551,936 B)
  - `upstream-go/bin/opera-proxy.linux-arm64` (7,667,872 B)

---

## 2. Rust Static Checks & Automated Tests

Working directory: `repo/rust/opera-proxy/` (`rustc 1.99.0`, `#![forbid(unsafe_code)]`):

| Command | Result |
| --- | --- |
| `cargo fmt --check` | **PASS** (0 diffs) |
| `cargo clippy --all-targets -- -D warnings` | **PASS** (0 warnings) |
| `cargo test --all-targets` | **PASS** — **39/39 passed** (27 unit + 7 mock integration + 5 edge-case tests) |
| `cargo test --doc` | **PASS** (0 failed) |

### Key Automated Test Coverage

- **CLI & Config (`src/cli/mod.rs`)**: Go flag syntax (`-flag`, `--flag`, `=`, bools), Go duration parser (`4h0m0s`, `1m30.5s`, `1h2m3s4ms5us6ns`, fractional & invalid units), `CSVArg` with leading spaces before quotes, space-delimited `-config` file parsing, OpenWrt UCI multi-instance args, mutual exclusion and validation exit codes.
- **TLS & `-fake-SNI` (`tests/integration_mock.rs`)**: Synthetic CA + server cert for `eu0.sec-tunnel.com`; verifies:
  1. Fake SNI (`www.google.com`) is sent in ClientHello while certificate is strictly verified against `eu0.sec-tunnel.com`.
  2. Empty SNI omits SNI extension while certificate is still strictly verified against `eu0.sec-tunnel.com`.
  3. Wrong expected hostname (`us0.sec-tunnel.com`) is **rejected** even with `-fake-SNI`.
  4. Untrusted CA is **rejected**.
- **SurfEasy Mock API (`tests/integration_mock.rs`)**: Full MD5 HTTP Digest Auth challenge/response verification, session cookie persistence across `register_subscriber` → `register_device` → `geo_list` → `discover`, API error `code=801` detection, and credential refresh via `subscriber_login` + `device_generate_password`.
- **Proxy Protocols (`tests/integration_mock.rs`, `tests/edge_cases.rs`)**:
  - Plain HTTP forward proxy with hop-by-hop header stripping (`Proxy-Connection`).
  - HTTP/1.1 `CONNECT` tunnel + 30 concurrent tunnels + clean shutdown.
  - HTTP/2 prior-knowledge `CONNECT` tunnel bidirectional relay.
  - HTTP `400 Bad Request` on missing scheme/host, `500` on forward failure, `502` on CONNECT failure.
  - SOCKS5 server (`-socks-mode`): CONNECT relay, remote domain pass-through (`ATYP=0x03`, no local DNS), RFC 1928 reply codes (`0x00`, `0x05`, `0x07`, `0xFF`).
- **Bootstrap DNS & Server Selection**: RFC 1035 A/AAAA wire codec, mock UDP DNS + `FastResolver` racing failing + working servers, `ServerSelection::Fastest` choosing faster mock TLS proxy, `probe_dialer` `dl_limit`.

---

## 3. Differential CLI Tests (Go vs Rust)

Compared `upstream-go/bin/opera-proxy-ref.exe` vs `repo/rust/opera-proxy/target/release/opera-proxy.exe` on 13 CLI scenarios:

- `-version` (`0`/`0`), unknown flag (`2`/`2`), empty `-country` (`2`/`2`), `-discover-repeat 0` (`2`/`2`), `-api-proxy-parallel 0` (`2`/`2`), invalid `-sort-proxies-by` (`2`/`2`), invalid `-server-selection` (`2`/`2`), mutually exclusive output flags (`2`/`2`), missing `-cafile` (`15`/`15`), missing `-proxy-blacklist` (`18`/`18`), invalid `-proxy` URL (`6`/`6`), unsupported `-proxy` scheme (`7`/`7`), missing `-api-proxy-file` (`8`/`8`).
- Result: **13/13 exact exit-code match**.

---

## 4. Real Router Hardware Verification (OpenWrt 24.10.1, MT6000 `aarch64_cortex-a53`)

All tests executed safely inside `/opt/test/opera-proxy-rust/` without modifying live router configuration:

1. **ELF / Static Linking**:
   - Python ELF verifier: `ELF64 LE`, `EM_AARCH64`, `static=True`, no `PT_INTERP`, no `libc.so.6`.
   - On router `ldd ./opera-proxy-rust`: `Not a valid dynamic program` (fully static musl binary).
2. **OpenWrt 24.10 `.ipk` Verification**:
   - `opkg --noaction install ./opera-proxy_1.32.0-1_aarch64_cortex-a53.ipk` → `Installing opera-proxy (1.32.0-1) to root...` (**PASS**).
   - Verified archive permissions (`0755` `/usr/bin/opera-proxy`, `0755` `/etc/init.d/opera-proxy`, `0644` `/etc/config/opera-proxy`), `conffiles` entry `/etc/config/opera-proxy`, and `sh -n /etc/init.d/opera-proxy` (**PASS**).
3. **Live SurfEasy API & Proxy Operations**:
   - `-version` → `v1.32.0-rust` (LuCI `get_version` compatible).
   - `-list-countries` → byte-for-byte identical CSV output to Go (`AM,Americas`, `EU,Europe`).
   - `-list-proxies` & `-dp-export` → exit code `0`, valid headers/format verified (credentials redacted).
   - Plain HTTP forward request (`connectivitycheck.gstatic.com/generate_204`) → HTTP `204`.
   - HTTPS `CONNECT` (`www.google.com/generate_204`) → HTTP `204`.
   - SOCKS5h (`-socks-mode -country AM`) → HTTP `204`.
   - LuCI `test_proxy` external IP check (`api.ipify.org`) → valid IP format detected (redacted).
   - 3 simultaneous Rust instances (HTTP EU + SOCKS5 AM + SOCKS5 EU) → all 3 returned HTTP `204` and exited `0` on `SIGTERM`.
4. **Bounded Soak Test (30 requests in 3 waves of 10 concurrent HTTPS requests)**:
   - Result: **30/30 HTTP 204**.
   - Baseline (+3s): `VmRSS=2280 kB`, `Threads=1`, `FDs=10`.
   - Post-soak (+3s): `VmRSS=2348 kB`, `VmHWM=2916 kB`, `VmSize=4712 kB`, `Threads=1`, `FDs=10` (zero FD or thread leaks).
   - `SIGTERM` exit code: `0`.

---

## 5. OpenWrt 25.12 `.apk` Verification (Built Strictly After 24.10.x)

Verified using the official OpenWrt 25.12.6 `apk-tools 3.0.5` (`aarch64`) binary in an isolated `--root` inside `/opt/test/opera-proxy-rust/`:

- `apk --root ... --arch aarch64_cortex-a53 --initdb add --allow-untrusted --no-network opera-proxy-1.32.0-r1-aarch64_cortex-a53-openwrt-25.12.apk` → `(1/1) Installing opera-proxy (1.32.0-r1) / OK: 2317 KiB in 1 packages` (**PASS**).
- Installed binary executed: `opera-proxy -version` → `v1.32.0-rust` (**PASS**).
- `apk info -L opera-proxy` listed `etc/config/opera-proxy`, `etc/init.d/opera-proxy`, `usr/bin/opera-proxy` (**PASS**).
- `apk del opera-proxy` → `(1/1) Purging opera-proxy (1.32.0-r1) / OK: 0 B in 0 packages`, clean removal verified (**PASS**).

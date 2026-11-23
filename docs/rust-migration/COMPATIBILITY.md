# Opera Proxy Go → Safe Rust Compatibility Matrix

## Pinned Reference Commits

- **Upstream Go source (`Alexey71/opera-proxy`)**: `41ae319812170ca1bcbc7e4e35ada2aad46509ea` (`v1.32.0`)
- **Packaging / LuCI / CI (`recrumptor/openwrt-opera-proxy-bin`)**: `81cef91cf647c8bc148f65532fc8746670f45bf9`
- **Target platforms**:
  - `aarch64_cortex-a53` (`mediatek/filogic`): OpenWrt `23.05.*` (`.ipk`), `24.10.*` (`.ipk`, live-verified on MT6000), `25.12.*` (`.apk`, verified via `apk-tools 3.0.5`) — `ring-crypto` provider
  - `mipsel_24kc` (`ramips/mt7621`, MIPS32r2 soft-float): OpenWrt `23.05.*` (`.ipk`), `24.10.*` (`.ipk`), `25.12.*` (`.apk`) — `pure-rust-crypto` (`rustls-rustcrypto`) provider, cross-compiled & ELF/soft-float ABI verified

> [!NOTE]
> Authoritative source of truth is the actual Go source (`main.go` and subpackages) at the pinned SHA above, not only `README.md`.
> Default API application secret literal from upstream is intentionally omitted from this document.

## Status Legend

- `PASS` — implemented in Safe Rust (`#![forbid(unsafe_code)]`) and verified by automated, differential, and/or real router tests
- `PARTIAL` — implemented with a documented security/behavioral deviation (see [LIMITATIONS.md](LIMITATIONS.md))
- `FAIL` — parity gap or failing verification
- `NOT TESTED` — not yet verified

---

## 1. CLI Flags (`main.go`)

| Flag | Type | Go Default (`main.go`) | Rust Module | Verification | Status |
| --- | --- | --- | --- | --- | --- |
| `-country` | string | `"EU"` | `cli` | Unit, diff exit code, live EU/AM on MT6000 | `PASS` |
| `-discover-csv` | string | `""` | `cli`, `seclient` | Integration test (`test_cli_exit_codes_and_csv_blacklist`) | `PASS` |
| `-list-countries` | bool | `false` | `cli`, `seclient` | Mock API + live Go vs Rust exact match on MT6000 | `PASS` |
| `-list-proxies` | bool | `false` | `cli`, `seclient` | Unit + live structure check (redacted) on MT6000 | `PASS` |
| `-list-proxies-all` | bool | `false` | `cli`, `seclient` | Unit flag implication + code parity | `PASS` |
| `-list-proxies-all-out` | string | `""` | `cli`, `seclient` | Unit flag implication + CSV writer | `PASS` |
| `-fetch-freeproxy-out` | string | `""` | `cli`, `seclient` | Unit HTML base64 parser + file writer | `PASS` |
| `-fetch-freeproxy-url` | string | `"https://advanced.name/freeproxy"` | `cli`, `seclient` | Unit pagination + parser | `PASS` |
| `-estimate-proxy-speed` | bool | `false` | `cli`, `dialer` | Unit + probe integration test | `PASS` |
| `-sort-proxies-by` | string | `"speed"` | `cli`, `seclient` | Unit + diff exit code (`speed`/`country`/`ip`) | `PASS` |
| `-dp-export` | bool | `false` | `cli`, `seclient` | Unit format test + live check on MT6000 | `PASS` |
| `-discover-repeat` | int | `1` | `cli`, `app` | Unit + diff exit code (`<1` -> exit 2) | `PASS` |
| `-bind-address` | string | `"127.0.0.1:18080"` | `cli`, `handler` | Unit + live multi-port on MT6000 | `PASS` |
| `-socks-mode` | bool | `false` | `cli`, `handler` | Unit + mock + live SOCKS5h on MT6000 | `PASS` |
| `-verbosity` | int | `20` | `cli`, `runtime` | Unit + silent mode on MT6000 | `PASS` |
| `-timeout` | duration | `30s` | `cli`, `runtime` | Unit Go duration parser + live tests | `PASS` |
| `-version` | bool | `false` | `cli` | Diff CLI + LuCI `get_version` check (`v1.32.0-rust`) | `PASS` |
| `-proxy` | string | `""` | `cli`, `dialer` | Diff exit codes (6/7) + HTTP/HTTPS/SOCKS5/SOCKS5h dialers | `PASS` |
| `-proxy-bypass` | CSV string | `""` (fallback `./proxy-bypass.txt`) | `cli`, `dialer` | Unit + handler bypass tests + fallback file test | `PASS` |
| `-api-client-version` | string | `"Stable 114.0.5282.21"` | `cli`, `seclient` | Unit + live SurfEasy API | `PASS` |
| `-api-client-type` | string | `"se0316"` | `cli`, `seclient` | Unit + live SurfEasy API | `PASS` |
| `-api-user-agent` | string | `"Mozilla/5.0 ... OPR/114.0.0.0"` | `cli`, `seclient` | Unit + live SurfEasy API | `PASS` |
| `-api-login` | string | `"se0316"` | `cli`, `seclient` | Mock Digest Auth + live SurfEasy API | `PASS` |
| `-api-password` | string | *(upstream Opera app default)* | `cli`, `seclient` | Mock Digest Auth + live SurfEasy API | `PASS` |
| `-api-address` | string | `""` | `cli`, `dialer` | FixedDialer + CLI flag | `PASS` |
| `-api-proxy` | string | `""` | `cli`, `dialer` | Normalization unit tests + dialer wiring | `PASS` |
| `-api-proxy-file` | string | `""` | `cli`, `app` | Diff exit code (8) + reader unit tests | `PASS` |
| `-api-proxy-list-url` | string | `""` | `cli`, `app` | HTTP fetcher + fallback to file | `PASS` |
| `-api-proxy-parallel` | int | `15` | `cli`, `app` | Diff exit code (2) + bounded semaphore | `PASS` |
| `-bootstrap-dns` | CSV string | 9 default DoH URLs | `cli`, `resolver` | Unit + UDP/FastResolver mock + live DoH on MT6000 | `PASS` |
| `-refresh` | duration | `4h0m0s` | `cli`, `runtime` | Wall-clock ticker unit test + mock refresh | `PASS` |
| `-refresh-retry` | duration | `5s` | `cli`, `runtime` | Ticker retry logic | `PASS` |
| `-init-retries` | int | `0` | `cli`, `runtime` | Retry unit tests (bounded & cancellable) | `PASS` |
| `-init-retry-interval` | duration | `5s` | `cli`, `runtime` | Retry cancellation test | `PASS` |
| `-cafile` | string | `""` | `cli`, `resolver` | Diff exit code (15) + custom CA verification test | `PASS` |
| `-fake-SNI` | string | `""` | `cli`, `dialer` | Verified on proxy TLS (strict cert check); see API TLS note in `LIMITATIONS.md` | `PARTIAL` |
| `-proxy-blacklist` | string | `""` | `cli`, `dialer` | Diff exit code (18) + CSV filtering integration test | `PASS` |
| `-override-proxy-address` | string | `""` | `cli`, `dialer` | Sanitizer unit tests + blacklist rejection | `PASS` |
| `-proxy-speed-test-url` | string | `https://ajax.googleapis.com/...` | `cli`, `dialer` | Probe integration test | `PASS` |
| `-proxy-speed-timeout` | duration | `15s` | `cli`, `dialer` | Probe timeout handling | `PASS` |
| `-proxy-speed-dl-limit` | int64 | `262144` | `cli`, `dialer` | Probe `dl_limit` integration test | `PASS` |
| `-server-selection` | enum | `"fastest"` | `cli`, `dialer` | Diff exit code (2) + fastest integration test + live MT6000 | `PASS` |
| `-server-selection-timeout` | duration | `60s` | `cli`, `dialer` | Selection timeout handling | `PASS` |
| `-server-selection-test-url` | string | `https://ajax.googleapis.com/...` | `cli`, `dialer` | Fastest probe integration + live MT6000 | `PASS` |
| `-server-selection-dl-limit` | int64 | `0` | `cli`, `dialer` | Probe `dl_limit` test | `PASS` |
| `-config` | file path | *(none)* | `cli` | Space-CSV config unit test | `PASS` |

---

## 2. Protocol, Network & Runtime Behaviors

| Feature / Behavior | Verification | Status |
| --- | --- | --- |
| Go-compatible flag syntax (`-flag`, `--flag`, `=`, bools, Go durations) | Unit + 13/13 differential CLI tests vs Go | `PASS` |
| Exit code parity (`0`, `2`, `6`, `7`, `8`, `15`, `18`, etc.) | 13/13 exact exit-code match vs Go reference | `PASS` |
| SurfEasy API HTTP Digest Auth + Cookie Jar + headers | Mock Digest server + live MT6000 registration/discover | `PASS` |
| Discover API error `code=801` fallback to `proxies.csv` | Mock API `801` test + CSV fallback loader | `PASS` |
| Bootstrap DNS (`dns://`, `udp://`, `tcp://`, `tls://`, `https://`, fastest-wins) | Unit RFC 1035 codec + UDP mock + live DoH on MT6000 | `PASS` |
| Upstream Opera TLS + `CONNECT` + Basic Auth + `-fake-SNI` with strict WebPKI cert verification | Synthetic CA mock TLS proxy (fake SNI, empty SNI, wrong host rejected, untrusted CA rejected) + live MT6000 | `PASS` |
| HTTP forward proxy (hop-by-hop removal, streaming, 400/500/502) | Mock tests + live HTTP 204 on MT6000 | `PASS` |
| HTTP/1.1 `CONNECT` & HTTP/2 `CONNECT` tunnels | Mock tests (H1 + H2 prior-knowledge) + live MT6000 | `PASS` |
| SOCKS5 server (`-socks-mode`, CONNECT, remote DNS pass-through, RFC 1928 reply codes) | Mock tests (domain pass-through, error codes) + live SOCKS5h on MT6000 | `PASS` |
| Wall-clock resilient refresh ticker & clean `SIGINT`/`SIGTERM` shutdown | Unit tests + `SIGTERM` exit code `0` on MT6000 | `PASS` |
| `#![forbid(unsafe_code)]`, `fmt`, `clippy -D warnings`, all unit/integration/doc tests | Clean pass on `rustc 1.99.0` | `PASS` |

---

## 3. OpenWrt Packaging & LuCI Integration Contract

| Component | Verification | Status |
| --- | --- | --- |
| Static ARM64 musl ELF (`aarch64-unknown-linux-musl`, no glibc) | ELF header validation + `ldd` on MT6000 (`Not a valid dynamic program`) | `PASS` |
| Static MIPSEL soft-float musl ELF (`mipsel-unknown-linux-musl`, no glibc) | ELF32 LE + `PT_MIPS_ABIFLAGS` (`MIPS32r2 fp_abi=3 SOFT ases=0x0`), static, 39/39 `pure-rust-crypto` tests (on-device MT7621 run pending hardware) | `PARTIAL` |
| OpenWrt 23.05.x `.ipk` (`aarch64_cortex-a53` & `mipsel_24kc`) | Packaged + ELF validated + OpenWrt 23.05 SDK CI job configured | `PASS` |
| OpenWrt 24.10.x `.ipk` (`aarch64_cortex-a53` & `mipsel_24kc`) | Live `opkg install` + `procd` + LuCI RPC verified on real MT6000 24.10.1 (`aarch64_cortex-a53`); `mipsel_24kc` packaged & ELF verified | `PASS` |
| OpenWrt 25.12.x `.apk` (`aarch64_cortex-a53` & `mipsel_24kc`) | Clean `apk add --allow-untrusted`, `opera-proxy -version`, `apk info -L`, `apk del` via official OpenWrt 25.12.6 `apk-tools 3.0.5` | `PASS` |
| UCI / procd / LuCI RPC contract (`get_version`, `test_proxy` HTTP & SOCKS5, 3 instances) | Verified binary/args/3-instance behavior in `/opt/test/` (live `/etc/config` untouched per rules) | `PASS` |
| Test-only GitHub Actions CI (no publish, Go fallback preserved) | `.github/workflows/rust-test.yml` added; `.github/workflows/build.yml` untouched | `PASS` |

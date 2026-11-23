# Benchmarks — Go vs Safe Rust on OpenWrt 24.10.1 (`aarch64_cortex-a53`)

## Test Hardware & Methodology

- **Device**: GL.iNet Flint 2 (MT6000) — MediaTek Filogic (`mediatek/filogic`, `aarch64_cortex-a53`, 4× Cortex-A53, 1 GB RAM)
- **OS**: OpenWrt `24.10.1` (`r28597-0425664679`), Linux `6.6.86 #0 SMP aarch64`
- **Binaries compared**:
  - **Go**: `Alexey71/opera-proxy` @ `41ae3198` (`v1.32.0`), built with Go `1.27.4`, `CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -trimpath` (uncompressed)
  - **Rust**: `opera-proxy` `v1.32.0-rust`, `rustc 1.99.0`, target `aarch64-unknown-linux-musl`, `opt-level="z"`, `lto=true`, `codegen-units=1`, `panic="abort"`, `strip=true`, `+crt-static`, `rust-lld` with `--fix-cortex-a53-843419` (uncompressed, no UPX)
- **Workload**: Identical script (`/opt/test/opera-proxy-rust/test_phase2_bench.sh`) sequentially running:
  1. HTTP proxy startup (`-country EU -server-selection fastest`) + readiness check (`generate_204`)
  2. SOCKS5 proxy startup (`-country AM -socks-mode -server-selection fastest`) + readiness check
  3. Plain HTTP forward request (`connectivitycheck.gstatic.com/generate_204`)
  4. 10 parallel HTTPS CONNECT requests (`www.google.com/generate_204`)
  5. 2 MiB HTTPS download via HTTP CONNECT and via SOCKS5h (`speed.cloudflare.com/__down?bytes=2097152`)
  6. Idle settlement (+3s) and clean `SIGTERM` shutdown
  7. Additional 3-instance simultaneous Rust test (HTTP EU + SOCKS5 AM + SOCKS5 EU) and 30-request soak test

---

## 1. Binary & Package Size Comparison (No UPX Required)

| Artifact | Go (`v1.32.0`) | Safe Rust (`v1.32.0-rust`) | Ratio |
| --- | ---: | ---: | ---: |
| Uncompressed ARM64 (`aarch64_cortex-a53`) binary | 7,667,872 B (7.31 MiB) | **2,371,888 B (2.26 MiB)** | **3.23× smaller** |
| OpenWrt 23.05 / 24.10 `.ipk` (`aarch64_cortex-a53`, no UPX) | ~2.5 MiB (with UPX) | **1,341,697 B (1.28 MiB)** | ~2× smaller without UPX |
| OpenWrt 25.12 `.apk` (`aarch64_cortex-a53`, no UPX) | ~2.5 MiB (with UPX) | **1,346,780 B (1.28 MiB)** | ~2× smaller without UPX |
| Uncompressed MIPSEL (`mipsel_24kc`, soft-float) binary | 9,175,231 B (8.75 MiB) | **3,521,344 B (3.36 MiB)** | **2.61× smaller** |
| OpenWrt 23.05 / 24.10 `.ipk` (`mipsel_24kc`, no UPX) | ~2.5 MiB (with UPX) | **1,495,763 B (1.43 MiB)** | Smaller without UPX |
| OpenWrt 25.12 `.apk` (`mipsel_24kc`, no UPX) | ~2.5 MiB (with UPX) | **1,500,360 B (1.43 MiB)** | Smaller without UPX |

> [!NOTE]
> UPX was omitted because the uncompressed Rust binary is already smaller than upstream's UPX-compressed Go binary, and uncompressed binaries avoid UPX decompression RAM overhead (allowing Linux to demand-page read-only text pages cleanly from flash/RAM).

---

## 2. Memory (RSS / VmHWM / VmSize), Threads & File Descriptors

| Measurement (`/proc/<pid>/status`) | Go (`v1.32.0`) | Safe Rust (`v1.32.0-rust`) | Reduction |
| --- | ---: | ---: | ---: |
| HTTP instance — idle `VmRSS` | 15,028 kB (14.68 MiB) | **2,280–2,404 kB (2.23–2.35 MiB)** | **6.25× – 6.59× less RAM** |
| HTTP instance — peak `VmHWM` (after 10 parallel + 2 MiB) | 15,668 kB (15.30 MiB) | **2,916 kB (2.85 MiB)** | **5.37× less peak RAM** |
| HTTP instance — steady post-load `VmRSS` (+3s) | 15,668 kB (15.30 MiB) | **2,348–2,388 kB (2.29–2.33 MiB)** | **6.56× less RAM** |
| SOCKS5 instance — idle & post-load `VmRSS` | 14,424 kB (14.09 MiB) | **2,288 kB (2.23 MiB)** | **6.30× less RAM** |
| Steady virtual memory (`VmSize`, post-3s) | 1,267,752 kB (1.21 GiB) | **4,712–4,720 kB (4.60 MiB)** | **269× smaller** |
| Steady OS threads (after bootstrap DNS) | 9–10 | **1** | 9–10× fewer |
| Open FDs (idle → post-load) | 10 → 11 | **10 → 10** | Zero leaks |
| **3 simultaneous instances total `VmRSS`** | ~44–46 MiB (extrapolated 3×15 MiB) | **7,240 kB (7.07 MiB measured)** | **~6.2× less RAM** |

---

## 3. Startup Latency, Concurrency & Throughput

> [!NOTE]
> Live download throughput depends on remote Opera proxy node load and internet routing at test time; both Go and Rust were tested back-to-back on the same router within 1 minute.

| Metric | Go (`v1.32.0`) | Safe Rust (`v1.32.0-rust`) |
| --- | --- | --- |
| Startup to first HTTP 204 (`-server-selection fastest`) | 2 s | 3 s |
| Plain HTTP forward proxy | HTTP 204 | HTTP 204 |
| 10× parallel HTTPS CONNECT | 10/10 | 10/10 |
| 30-request soak test (3 waves × 10 parallel, Rust) | *(not run for Go)* | 30/30 |
| 2 MiB HTTPS download (HTTP CONNECT, EU) | 0.705 s (2.97 MB/s) | 0.639 s (3.28 MB/s) |
| 2 MiB HTTPS download (SOCKS5h, AM) | 1.518 s (1.38 MB/s) | 1.547 s (1.36 MB/s) |
| Clean `SIGTERM` exit code | `0` | `0` |

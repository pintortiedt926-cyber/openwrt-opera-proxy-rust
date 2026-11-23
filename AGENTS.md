# AGENTS.md — OpenWrt Opera Proxy (Safe Rust)

Отвечать пользователю всегда на русском языке.

## Текущий статус проекта

Миграция `opera-proxy` с Go на **100% Safe Rust** завершена (базовый эталон: `Alexey71/opera-proxy` `v1.32.0` @ `41ae3198`, упаковка/LuCI: `recrumptor/openwrt-opera-proxy-bin` @ `81cef91c`).

Поддерживаемые таргеты:
- **`aarch64_cortex-a53`** (`mediatek/filogic`): OpenWrt `23.05.*` (`.ipk`), `24.10.*` (`.ipk`, проверено на реальном MT6000), `25.12.*` (`.apk`, проверено через `apk-tools 3.0.5`) — криптопровайдер `ring-crypto` (по умолчанию).
- **`mipsel_24kc`** (`ramips/mt7621`, MIPS32r2 soft-float): OpenWrt `23.05.*` (`.ipk`), `24.10.*` (`.ipk`), `25.12.*` (`.apk`) — криптопровайдер `pure-rust-crypto` (`rustls-rustcrypto`), сборка через `nightly` + `-Z build-std=core,alloc,std,panic_abort`.

## Обязательные инварианты (не нарушать)

1. **Только Safe Rust**: `#![forbid(unsafe_code)]` в `src/lib.rs`, `src/main.rs` и `tests/*.rs`. Без привязок к `glibc` и `OpenSSL`.
2. **Строгий TLS**: никогда не отключать проверку сертификатов (`InsecureSkipVerify` запрещён). `-fake-SNI` допускается только с проверкой реального имени хоста через `OverrideServerNameVerifier` и `RootCertStore`.
3. **Низкое потребление памяти (цель ~2–3 MiB RSS на инстанс)**:
   - Сохранять однопоточный Tokio-рантайм (`new_current_thread`) с ограниченным blocking-пулом (`max_blocking_threads(4)`).
   - Держать буферы релея ограниченными (`RELAY_BUF_SIZE = 16 KiB`) и лимит одновременных подключений (`MAX_CONCURRENT_CONNS = 256`).
   - Не тащить тяжёлые зависимости (`reqwest`, `regex`, `hickory-dns`, `chrono`, `clap`).
4. **Совместимость с OpenWrt и LuCI**:
   - Не ломать путь `/usr/bin/opera-proxy`, формат флагов Go (`-flag value` / `--flag=value`), коды выхода, вывод `-version`, UCI `/etc/config/opera-proxy` (`conffiles`), `procd` `/etc/init.d/opera-proxy` и все методы `luci.opera-proxy`.
   - Для `mipsel_24kc` обязательно сохранять `soft-float` (`PT_MIPS_ABIFLAGS` `fp_abi=3`) и отсутствие 64-битных атомиков (`AtomicU64`/`AtomicI64`).
5. **Безопасность и гигиена Git**:
   - Никогда не коммитить секреты, токены, куки, реальные IP, локальные пути хоста, `target/`, `.ipk`/`.apk`, кеши SDK.
   - Не пушить коммиты, не публиковать GitHub Releases и не изменять живую систему роутера вне `/opt/test/` без прямого запроса пользователя.

## Команды проверки перед любым изменением

```bash
cargo fmt --manifest-path rust/opera-proxy/Cargo.toml --check
cargo clippy --manifest-path rust/opera-proxy/Cargo.toml --all-targets -- -D warnings
cargo clippy --manifest-path rust/opera-proxy/Cargo.toml --no-default-features --features pure-rust-crypto --all-targets -- -D warnings
cargo test --manifest-path rust/opera-proxy/Cargo.toml --all-targets
cargo test --manifest-path rust/opera-proxy/Cargo.toml --no-default-features --features pure-rust-crypto --all-targets
cargo test --manifest-path rust/opera-proxy/Cargo.toml --doc
```

При изменении упаковки проверять ELF-заголовки и ABI через `scripts/package_openwrt.py` (для `aarch64_cortex-a53` и `mipsel_24kc`).

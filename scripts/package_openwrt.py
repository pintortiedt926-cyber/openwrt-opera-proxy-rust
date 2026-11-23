#!/usr/bin/env python3
"""Validate ARM64 / MIPSEL musl ELF binary and package OpenWrt .ipk (23.05/24.10) or .apk (25.12)."""

import argparse
import gzip
import hashlib
import io
import struct
import sys
import tarfile
import time
from pathlib import Path

EM_MIPS = 8
EM_AARCH64 = 183
PT_INTERP = 3


def validate_elf(bin_path: Path, arch: str) -> dict:
    data = bin_path.read_bytes()
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ValueError(f"{bin_path} is not a valid ELF file")
    ei_class = data[4]
    ei_data = data[5]
    if ei_data != 1:
        raise ValueError(f"Expected little-endian ELF (data=1), got {ei_data}")

    e_type, e_machine = struct.unpack_from("<HH", data, 16)
    if arch == "aarch64_cortex-a53":
        if ei_class != 2:
            raise ValueError(f"Expected ELF64 (class=2) for {arch}, got {ei_class}")
        if e_machine != EM_AARCH64:
            raise ValueError(f"Expected EM_AARCH64 ({EM_AARCH64}), got {e_machine}")
        e_phoff = struct.unpack_from("<Q", data, 32)[0]
        e_flags = struct.unpack_from("<I", data, 48)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 54)
        machine_name = "AArch64"
    elif arch == "mipsel_24kc":
        if ei_class != 1:
            raise ValueError(f"Expected ELF32 (class=1) for {arch}, got {ei_class}")
        if e_machine != EM_MIPS:
            raise ValueError(f"Expected EM_MIPS ({EM_MIPS}), got {e_machine}")
        e_phoff = struct.unpack_from("<I", data, 28)[0]
        e_flags = struct.unpack_from("<I", data, 36)[0]
        e_phentsize, e_phnum = struct.unpack_from("<HH", data, 42)
        machine_name = "MIPS (little-endian)"
    else:
        raise ValueError(f"Unsupported OpenWrt package architecture: {arch}")

    interp = None
    mips_abiflags = None
    for i in range(e_phnum):
        off = e_phoff + i * e_phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        if p_type == PT_INTERP:
            if ei_class == 2:
                p_offset = struct.unpack_from("<Q", data, off + 8)[0]
                p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
            else:
                p_offset = struct.unpack_from("<I", data, off + 4)[0]
                p_filesz = struct.unpack_from("<I", data, off + 16)[0]
            interp = data[p_offset : p_offset + p_filesz].rstrip(b"\x00").decode("utf-8", "replace")
        elif arch == "mipsel_24kc" and p_type == 0x70000003:  # PT_MIPS_ABIFLAGS
            p_offset = struct.unpack_from("<I", data, off + 4)[0]
            vals = struct.unpack_from("<HBBBBBBIIII", data, p_offset)
            mips_abiflags = (vals[1], vals[2], vals[6], vals[8])  # isa_lvl, isa_rev, fp_abi, ases

    if arch == "mipsel_24kc" and mips_abiflags is not None:
        isa_lvl, isa_rev, fp_abi, ases = mips_abiflags
        if fp_abi != 3:
            raise ValueError(
                f"Expected MIPS soft-float ABI (fp_abi=3) for mipsel_24kc, got fp_abi={fp_abi}"
            )
        machine_name = f"MIPS{isa_lvl}r{isa_rev} LE (soft-float, ases=0x{ases:x})"

    if interp and ("glibc" in interp or "ld-linux" in interp):
        raise ValueError(f"Binary unexpectedly requires glibc interpreter: {interp}")
    if b"libc.so.6" in data:
        raise ValueError("Binary unexpectedly references libc.so.6 (glibc)")

    return {
        "arch": arch,
        "size": len(data),
        "e_type": e_type,
        "e_machine": machine_name,
        "e_flags": f"0x{e_flags:08x}",
        "static": interp is None,
        "interp": interp or "none (statically linked)",
        "sha256": hashlib.sha256(data).hexdigest(),
    }


def _add_bytes_to_tar(
    tf: tarfile.TarFile,
    name: str,
    payload: bytes,
    mode: int,
    mtime: int,
    with_apk_sha1: bool = False,
) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(payload)
    info.mode = mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = mtime
    if with_apk_sha1:
        info.pax_headers = {"APK-TOOLS.checksum.SHA1": hashlib.sha1(payload).hexdigest()}
    tf.addfile(info, io.BytesIO(payload))


def _add_dir_to_tar(tf: tarfile.TarFile, name: str, mtime: int) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = mtime
    tf.addfile(info)


def _gzip_bytes(raw: bytes, mtime: int) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=buf, compresslevel=9, mtime=mtime) as gz:
        gz.write(raw)
    return buf.getvalue()


def _read_lf_text(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def build_ipk(
    repo_root: Path, binary_path: Path, arch: str, version: str, release: str, out_path: Path
) -> None:
    mtime = int(time.time())
    pkg_dir = repo_root / "opera-proxy"
    init_script = _read_lf_text(pkg_dir / "files" / "etc" / "init.d" / "opera-proxy")
    uci_config = _read_lf_text(pkg_dir / "files" / "etc" / "config" / "opera-proxy")
    bin_bytes = binary_path.read_bytes()

    data_tar_buf = io.BytesIO()
    with tarfile.open(fileobj=data_tar_buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        for d in ["./etc", "./etc/config", "./etc/init.d", "./usr", "./usr/bin"]:
            _add_dir_to_tar(tf, d, mtime)
        _add_bytes_to_tar(tf, "./etc/config/opera-proxy", uci_config, 0o644, mtime)
        _add_bytes_to_tar(tf, "./etc/init.d/opera-proxy", init_script, 0o755, mtime)
        _add_bytes_to_tar(tf, "./usr/bin/opera-proxy", bin_bytes, 0o755, mtime)
    data_tar_gz = _gzip_bytes(data_tar_buf.getvalue(), mtime)

    installed_size_kb = (len(bin_bytes) + len(init_script) + len(uci_config) + 1023) // 1024
    control_text = (
        f"Package: opera-proxy\n"
        f"Version: {version}-{release}\n"
        f"Depends: libc\n"
        f"Source: opera-proxy\n"
        f"SourceName: opera-proxy\n"
        f"License: MIT\n"
        f"Section: net\n"
        f"Maintainer: Snawoot <vladislav-ex-gh@vm-0.com>\n"
        f"Architecture: {arch}\n"
        f"Installed-Size: {installed_size_kb}\n"
        f"Description: Opera Proxy client (Safe Rust port for OpenWrt {arch})\n"
    ).encode("utf-8")
    conffiles_text = b"/etc/config/opera-proxy\n"

    ctrl_tar_buf = io.BytesIO()
    with tarfile.open(fileobj=ctrl_tar_buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        _add_bytes_to_tar(tf, "./control", control_text, 0o644, mtime)
        _add_bytes_to_tar(tf, "./conffiles", conffiles_text, 0o644, mtime)
    ctrl_tar_gz = _gzip_bytes(ctrl_tar_buf.getvalue(), mtime)

    outer_tar_buf = io.BytesIO()
    with tarfile.open(fileobj=outer_tar_buf, mode="w", format=tarfile.GNU_FORMAT) as tf:
        _add_bytes_to_tar(tf, "./debian-binary", b"2.0\n", 0o644, mtime)
        _add_bytes_to_tar(tf, "./data.tar.gz", data_tar_gz, 0o644, mtime)
        _add_bytes_to_tar(tf, "./control.tar.gz", ctrl_tar_gz, 0o644, mtime)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(_gzip_bytes(outer_tar_buf.getvalue(), mtime))


def build_apk(
    repo_root: Path, binary_path: Path, arch: str, version: str, release: str, out_path: Path
) -> None:
    mtime = int(time.time())
    pkg_dir = repo_root / "opera-proxy"
    init_script = _read_lf_text(pkg_dir / "files" / "etc" / "init.d" / "opera-proxy")
    uci_config = _read_lf_text(pkg_dir / "files" / "etc" / "config" / "opera-proxy")
    bin_bytes = binary_path.read_bytes()

    data_buf = io.BytesIO()
    with tarfile.open(fileobj=data_buf, mode="w", format=tarfile.PAX_FORMAT) as tf:
        for d in ["etc", "etc/config", "etc/init.d", "usr", "usr/bin"]:
            _add_dir_to_tar(tf, d, mtime)
        _add_bytes_to_tar(tf, "etc/config/opera-proxy", uci_config, 0o644, mtime, with_apk_sha1=True)
        _add_bytes_to_tar(tf, "etc/init.d/opera-proxy", init_script, 0o755, mtime, with_apk_sha1=True)
        _add_bytes_to_tar(tf, "usr/bin/opera-proxy", bin_bytes, 0o755, mtime, with_apk_sha1=True)
    data_gz = _gzip_bytes(data_buf.getvalue(), mtime)
    datahash = hashlib.sha256(data_gz).hexdigest()

    total_size = len(bin_bytes) + len(init_script) + len(uci_config)
    pkginfo = (
        f"pkgname = opera-proxy\n"
        f"pkgver = {version}-r{release}\n"
        f"pkgdesc = Opera Proxy client (Safe Rust port for OpenWrt {arch})\n"
        f"url = https://github.com/Alexey71/opera-proxy\n"
        f"builddate = {mtime}\n"
        f"packager = openwrt-opera-proxy-rust\n"
        f"size = {total_size}\n"
        f"arch = {arch}\n"
        f"origin = opera-proxy\n"
        f"maintainer = Snawoot <vladislav-ex-gh@vm-0.com>\n"
        f"license = MIT\n"
        f"datahash = {datahash}\n"
    ).encode("utf-8")

    ctrl_buf = io.BytesIO()
    with tarfile.open(fileobj=ctrl_buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        _add_bytes_to_tar(tf, ".PKGINFO", pkginfo, 0o644, mtime)
    entry_blocks = 512 + ((len(pkginfo) + 511) // 512) * 512
    ctrl_gz = _gzip_bytes(ctrl_buf.getvalue()[:entry_blocks], mtime)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(ctrl_gz + data_gz)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", required=True, type=Path)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--arch", choices=["aarch64_cortex-a53", "mipsel_24kc"], default="aarch64_cortex-a53")
    parser.add_argument("--version", default="1.32.0")
    parser.add_argument("--release", default="1")
    parser.add_argument("--format", choices=["ipk", "apk"], default="ipk")
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()

    info = validate_elf(args.binary, args.arch)
    print(f"ELF validation PASS: {info}")

    if args.format == "ipk":
        build_ipk(args.repo_root, args.binary, args.arch, args.version, args.release, args.output)
        print(f"Built OpenWrt .ipk ({args.arch}): {args.output} ({args.output.stat().st_size} bytes)")
    else:
        build_apk(args.repo_root, args.binary, args.arch, args.version, args.release, args.output)
        print(f"Built OpenWrt 25.12 .apk ({args.arch}): {args.output} ({args.output.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())

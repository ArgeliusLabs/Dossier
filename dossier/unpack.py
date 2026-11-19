"""Safe unpacking of .crx (v2/v3), .xpi and .zip packages.

Extension packages are untrusted input. We never execute anything from them; we only
extract to a fresh temp directory with zip-slip, symlink and zip-bomb protection.
"""
from __future__ import annotations

import io
import os
import struct
import zipfile
from pathlib import Path, PurePosixPath

MAX_TOTAL_BYTES = 600 * 1024 * 1024   # uncompressed
MAX_FILES = 30_000
MAX_RATIO = 200                        # per-file compression ratio guard


class UnpackError(Exception):
    pass


def crx_to_zip_bytes(data: bytes) -> bytes:
    """Strip a CRX2/CRX3 header and return the embedded zip archive."""
    if data[:4] != b"Cr24":
        if data[:2] == b"PK":
            return data  # already a zip
        raise UnpackError("Not a CRX or ZIP file (bad magic bytes).")
    version = struct.unpack("<I", data[4:8])[0]
    if version == 2:
        pub_len, sig_len = struct.unpack("<II", data[8:16])
        offset = 16 + pub_len + sig_len
    elif version == 3:
        header_len = struct.unpack("<I", data[8:12])[0]
        offset = 12 + header_len
    else:
        raise UnpackError(f"Unsupported CRX version {version}.")
    if data[offset:offset + 2] != b"PK":
        # Some packers pad; search a little for the zip signature.
        idx = data.find(b"PK\x03\x04", offset, offset + 4096)
        if idx < 0:
            raise UnpackError("CRX header parsed but no ZIP payload found.")
        offset = idx
    return data[offset:]


def _safe_member_path(dest: Path, name: str) -> Path | None:
    name = name.replace("\\", "/")
    p = PurePosixPath(name)
    if p.is_absolute() or any(part in ("..", "") for part in p.parts if part != "."):
        return None
    if not p.parts or ":" in p.parts[0]:   # empty or Windows drive letter
        return None
    target = (dest / Path(*p.parts)).resolve()
    if not str(target).startswith(str(dest.resolve())):
        return None
    return target


def extract_package(data: bytes, dest: Path) -> dict:
    """Extract a CRX/XPI/ZIP byte string into ``dest``. Returns stats incl. skipped entries."""
    zbytes = crx_to_zip_bytes(data)
    try:
        zf = zipfile.ZipFile(io.BytesIO(zbytes))
    except zipfile.BadZipFile as e:
        raise UnpackError(f"Corrupt archive: {e}") from e

    dest.mkdir(parents=True, exist_ok=True)
    total = 0
    skipped: list[str] = []
    count = 0
    for info in zf.infolist():
        if info.is_dir():
            continue
        count += 1
        if count > MAX_FILES:
            raise UnpackError(f"Archive has more than {MAX_FILES} files; refusing (possible zip bomb).")
        # Reject symlinks stored in the zip's external attributes.
        if (info.external_attr >> 16) & 0o170000 == 0o120000:
            skipped.append(f"{info.filename} (symlink)")
            continue
        target = _safe_member_path(dest, info.filename)
        if target is None:
            skipped.append(f"{info.filename} (unsafe path)")
            continue
        if info.compress_size and info.file_size / max(info.compress_size, 1) > MAX_RATIO and info.file_size > 10_000_000:
            skipped.append(f"{info.filename} (suspicious compression ratio)")
            continue
        total += info.file_size
        if total > MAX_TOTAL_BYTES:
            raise UnpackError("Archive expands beyond size limit; refusing (possible zip bomb).")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zf.open(info) as src, open(target, "wb") as out:
            out.write(src.read())
    return {"files": count, "uncompressed_bytes": total, "skipped": skipped}


def find_manifest_root(path: Path) -> Path:
    """Return the directory containing manifest.json (handles one level of nesting)."""
    if (path / "manifest.json").is_file():
        return path
    candidates = sorted(path.rglob("manifest.json"), key=lambda p: len(p.parts))
    for c in candidates:
        if "node_modules" in c.parts:
            continue
        return c.parent
    raise UnpackError(f"No manifest.json found under {path}")


def iter_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if not d.startswith(".git")]
        for fn in filenames:
            p = Path(dirpath) / fn
            if p.is_symlink():
                continue
            yield p

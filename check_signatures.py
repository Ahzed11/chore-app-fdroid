#!/usr/bin/env python3
"""Fail the F-Droid rebuild if any APK was signed with a key other than the pinned one.

Android refuses to install an update whose signing key changed, so an index
that contains an APK signed with any key but the expected one bricks updates
for every installed user (the chore-app v1.0.0/v1.0.1 incident: both shipped
debug-signed on throwaway keys).

This guard is STRONGER than a cross-version consistency check. It:

  1. re-extracts the actual signing certificate from every .apk in the repo
     (APK Signature Scheme v2) — it does not trust the index metadata;
  2. compares each APK's certificate SHA-256 against the PINNED value in
     `signing_cert.sha256` (the single source of truth, committed here);
  3. cross-checks that every version's `signer` field in index-v1.json also
     equals the pinned value.

Because it validates against an absolute pin (not "matches the newest
version"), it catches a keystore rotation even when the repo contains a
single version, and it catches a wrong `signer` written by the index tooling.

The pin MUST stay equal to `ANDROID_APK_CERT_SHA256` in Ahzed11/chore-app's
CI secrets. Changing the keystore is a user-visible migration (uninstall +
reinstall) and requires updating BOTH values deliberately — never silently.

Usage: check_signatures.py <repo-dir>   (repo-dir is typically fdroid/repo)

Exit 0 on consistency, 1 on drift (update.sh turns a nonzero exit into
"no commit, no push").
"""
import glob
import hashlib
import json
import os
import struct
import sys

V2_BLOCK_ID = 0x7109871A  # APK Signature Scheme v2
MAGIC = b"APK Sig Block 42"


def _u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def _u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def _apk_signing_block(apk_path):
    """Return the raw APK Signing Block bytes (leading size field included)."""
    with open(apk_path, "rb") as f:
        f.seek(0, 2)
        file_len = f.tell()
        # EOCD can be shifted by a ZIP comment — scan the last 64 KiB.
        scan = min(file_len, 65557)
        f.seek(file_len - scan)
        tail = f.read(scan)
        eocd = tail.rfind(b"PK\x05\x06")
        if eocd < 0:
            raise ValueError("no EOCD found")
        cd_offset = struct.unpack_from("<I", tail, eocd + 16)[0]
        f.seek(cd_offset - 24)
        footer = f.read(24)
        if footer[8:24] != MAGIC:
            raise ValueError("no APK Signing Block 42 (v1-only signed?)")
        size = _u64(footer, 0)
        f.seek(cd_offset - 8 - size)
        block = f.read(8 + size)
        if _u64(block, 0) != size:
            raise ValueError("signing block leading-size mismatch")
        return block


def apk_signer_cert_sha256(apk_path):
    """SHA-256 of the v2 signer certificate — the same value F-Droid records
    as `signer` in index-v1.json."""
    block = _apk_signing_block(apk_path)
    pos, end = 8, len(block) - 24
    for _ in range(1000):  # hard cap so a malformed length can never loop
        if pos >= end:
            break
        length = _u64(block, pos)
        pair_id = _u32(block, pos + 8)
        if pair_id == V2_BLOCK_ID:
            value = block[pos + 12 : pos + 8 + length]
            slen = _u32(value, 0)
            signer = value[4 : 4 + slen]
            sd_len = _u32(signer, 0)
            signed_data = signer[4 : 4 + sd_len]
            # First DER SEQUENCE (30 82) inside signedData is the certificate.
            idx = signed_data.find(b"\x30\x82")
            if idx >= 0:
                der_len = struct.unpack_from(">H", signed_data, idx + 2)[0]
                cert = signed_data[idx : idx + 4 + der_len]
                return hashlib.sha256(cert).hexdigest()
        pos += 8 + length
    raise ValueError("no v2 signer block found")


def _load_pin() -> str:
    pin_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "signing_cert.sha256"
    )
    if not os.path.exists(pin_path):
        print(
            "ERROR: signing_cert.sha256 is missing — refusing to verify APK "
            "signing keys against an unknown pin.",
            file=sys.stderr,
        )
        return ""
    with open(pin_path) as f:
        pin = f.read().strip().lower()
    if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        print(
            f"ERROR: signing_cert.sha256 must contain exactly one 64-char hex "
            f"certificate SHA-256 (got {len(pin)} chars).",
            file=sys.stderr,
        )
        return ""
    return pin


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    repo_dir = sys.argv[1]
    expected = _load_pin()
    if not expected:
        return 1

    problems = []

    # 1. Re-extract the actual certificate from every APK; compare to the pin.
    apks = sorted(glob.glob(os.path.join(repo_dir, "*.apk")))
    if not apks:
        print(f"WARNING: no .apk files found under {repo_dir}", file=sys.stderr)
    apk_certs = {}
    for apk in apks:
        name = os.path.basename(apk)
        try:
            actual = apk_signer_cert_sha256(apk)
        except Exception as e:  # noqa: BLE001 - report and keep going
            problems.append(f"{name}: could not extract signing cert ({e})")
            continue
        apk_certs[name] = actual
        if actual != expected:
            problems.append(f"{name}: APK signer {actual} != pinned {expected}")

    # 2. Cross-check every version's `signer` field in the index against the pin.
    index_path = os.path.join(repo_dir, "index-v1.json")
    if os.path.exists(index_path):
        with open(index_path) as f:
            index = json.load(f)
        for package, versions in index.get("packages", {}).items():
            for v in versions:
                signer = (v.get("signer") or "").lower()
                if signer != expected:
                    problems.append(
                        f"index {package} {v.get('versionName')} "
                        f"(code {v.get('versionCode')}): signer "
                        f"{signer or '(missing)'} != pinned {expected}"
                    )

    if problems:
        print(
            "ERROR: signing-key drift detected — updates would be blocked for "
            "installed users (Android refuses signature changes):",
            file=sys.stderr,
        )
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        print(f"  Pinned cert (signing_cert.sha256): {expected}", file=sys.stderr)
        print(
            "  The APK keystore must never change silently. Restore the original "
            "keystore secrets in Ahzed11/chore-app, or — only for a deliberate "
            "uninstall/reinstall migration — update signing_cert.sha256 AND the "
            "ANDROID_APK_CERT_SHA256 secret together.",
            file=sys.stderr,
        )
        return 1

    print(
        f"OK: {len(apks)} APK(s) + index all signed with pinned cert {expected}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())

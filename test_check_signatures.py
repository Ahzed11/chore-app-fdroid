"""Tests of check_signatures.py: the guard runs on synthetic APKs that carry an APK Signing Block v2
with a chosen certificate, so no Android tooling is needed.

Run: python3 -m unittest test_check_signatures
"""
import hashlib
import io
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "check_signatures.py")


def certificate(seed):
    """A DER-looking blob: SEQUENCE (30 82) with a 2-byte length."""
    body = hashlib.sha256(seed.encode()).digest() * 4
    return b"\x30\x82" + struct.pack(">H", len(body)) + body


def cert_sha256(seed):
    return hashlib.sha256(certificate(seed)).hexdigest()


def signing_block(cert):
    signed_data = b"\x00\x00" + cert
    signer = struct.pack("<I", len(signed_data)) + signed_data
    value = struct.pack("<I", len(signer)) + signer
    pair = struct.pack("<QI", len(value) + 4, 0x7109871A) + value
    size = len(pair) + 8 + 16
    return struct.pack("<Q", size) + pair + struct.pack("<Q", size) + b"APK Sig Block 42"


def write_apk(path, seed):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes.dex", b"dex")
    data = buf.getvalue()
    eocd = data.rfind(b"PK\x05\x06")
    cd_offset = struct.unpack_from("<I", data, eocd + 16)[0]
    block = signing_block(certificate(seed))
    patched = bytearray(data[:cd_offset] + block + data[cd_offset:])
    struct.pack_into("<I", patched, eocd + len(block) + 16, cd_offset + len(block))
    with open(path, "wb") as f:
        f.write(patched)


class Guard(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.root)
        shutil.copy(SCRIPT, self.root)
        self.repo = os.path.join(self.root, "repo")
        os.mkdir(self.repo)
        self.packages = {}
        self.write("signing_cert.sha256", cert_sha256("chore") + "\n")

    def write(self, name, text):
        with open(os.path.join(self.root, name), "w") as f:
            f.write(text)

    def add(self, package, apk, seed, signer_seed=None):
        write_apk(os.path.join(self.repo, apk), seed)
        self.packages.setdefault(package, []).append(
            {"apkName": apk, "versionName": "1", "versionCode": 1, "signer": cert_sha256(signer_seed or seed)}
        )

    def run_guard(self):
        with open(os.path.join(self.repo, "index-v1.json"), "w") as f:
            json.dump({"packages": self.packages}, f)
        return subprocess.run(
            [sys.executable, os.path.join(self.root, "check_signatures.py"), self.repo], capture_output=True, text=True
        )

    def test_default_pin_applies_to_an_app_without_an_entry(self):
        self.add("dev.chore", "chore_1.apk", "chore")
        r = self.run_guard()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_two_apps_each_with_their_own_pin(self):
        self.write("signing_certs.json", json.dumps({"com.better": cert_sha256("better")}))
        self.add("dev.chore", "chore_1.apk", "chore")
        self.add("com.better", "better_1.apk", "better")
        r = self.run_guard()
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_a_new_app_without_a_pin_is_refused(self):
        self.add("dev.chore", "chore_1.apk", "chore")
        self.add("com.better", "better_1.apk", "better")
        r = self.run_guard()
        self.assertEqual(r.returncode, 1)
        self.assertIn("better_1.apk: APK signer", r.stderr)
        self.assertIn("index com.better", r.stderr)

    def test_chore_app_signed_with_another_key_is_still_refused(self):
        self.write("signing_certs.json", json.dumps({"com.better": cert_sha256("better")}))
        self.add("dev.chore", "chore_2.apk", "better")
        r = self.run_guard()
        self.assertEqual(r.returncode, 1)
        self.assertIn("chore_2.apk", r.stderr)

    def test_betterhome_with_the_key_of_chore_app_is_refused(self):
        self.write("signing_certs.json", json.dumps({"com.better": cert_sha256("better")}))
        self.add("com.better", "better_1.apk", "chore")
        r = self.run_guard()
        self.assertEqual(r.returncode, 1)
        self.assertIn("better_1.apk", r.stderr)

    def test_an_index_signer_that_differs_from_the_apk_is_refused(self):
        self.add("dev.chore", "chore_1.apk", "chore", signer_seed="other")
        r = self.run_guard()
        self.assertEqual(r.returncode, 1)
        self.assertIn("index dev.chore", r.stderr)

    def test_unusable_pin_file_refuses_to_verify(self):
        self.add("dev.chore", "chore_1.apk", "chore")
        for content in ("not json", json.dumps({"com.better": "abc"}), json.dumps(["x"])):
            self.write("signing_certs.json", content)
            r = self.run_guard()
            self.assertEqual(r.returncode, 1, content)
            self.assertIn("signing_certs.json", r.stderr)

    def test_the_committed_pin_file_is_valid(self):
        with open(os.path.join(HERE, "signing_certs.json")) as f:
            pins = json.load(f)
        for package, pin in pins.items():
            self.assertEqual(len(pin), 64, package)
            int(pin, 16)


if __name__ == "__main__":
    unittest.main()

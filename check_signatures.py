#!/usr/bin/env python3
"""Fail if any package version in an F-Droid index was signed with a key
different from the newest version of that package.

Android refuses to install an update whose signing key changed, so a repo
index that mixes signers for one app silently bricks updates for everyone
(the chore-app v1.0.0/1.0.1 incident: both debug-signed on throwaway keys).
This guard runs in update.sh BEFORE the regenerated index is committed and
pushed (see TASK-100). The keystore must never change silently; changing it
deliberately requires an uninstall/reinstall migration for all users.

Usage: check_signatures.py <path-to-index-v1.json>
Exit 0 on consistency, 1 on drift.
"""
import json
import sys


def main():
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    with open(sys.argv[1]) as f:
        index = json.load(f)

    bad = []
    for package, versions in index.get("packages", {}).items():
        if not versions:
            continue
        newest = max(versions, key=lambda v: v.get("versionCode", 0))
        newest_signer = newest.get("signer")
        for version in versions:
            if version.get("signer") != newest_signer:
                bad.append((package, version, newest))

    if not bad:
        print(f"OK: {len(index.get('packages', {}))} package(s), all versions "
              f"signed consistently with the newest version")
        return 0

    print("ERROR: signing-key drift detected — updates would be blocked for "
          "installed users (Android refuses signature changes):", file=sys.stderr)
    for package, version, newest in bad:
        print(f"  package: {package}", file=sys.stderr)
        print(f"    version {version.get('versionName')} (code "
              f"{version.get('versionCode')}) signer: {version.get('signer')}",
              file=sys.stderr)
        print(f"    newest version {newest.get('versionName')} (code "
              f"{newest.get('versionCode')}) signer: {newest.get('signer')}",
              file=sys.stderr)
    print("  The APK signing keystore must never change silently. Restore the "
          "original keystore, or plan an uninstall/reinstall migration and "
          "republish (see TASK-099).", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())

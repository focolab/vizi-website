#!/usr/bin/env python3
"""Verify the accepted-plugin catalog (_data/plugins.yml).

Two uses:

  python script/verify-plugins.py
      Validate the shape of every entry, and for every LIVE (non-pending)
      entry re-download its asset_url and check the byte size and sha256
      match what the entry declares. Exits non-zero on any problem. Run this
      when accepting a version, and gate it in CI.

  python script/verify-plugins.py --fetch <asset_url>
      Download one asset and print its sha256 and size, to paste into a new
      entry. (Does not touch the catalog.)

Only depends on the standard library plus PyYAML (`pip install pyyaml`).
The field contract it enforces is the one frozen in _data/plugins.yml.
"""
from __future__ import annotations

import argparse
import hashlib
import re
import sys
import urllib.request
from pathlib import Path

try:
    import yaml
except ImportError:
    sys.exit("verify-plugins: needs PyYAML — `pip install pyyaml`")

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "_data" / "plugins.yml"

REQUIRED_STR = ["id", "name", "summary", "repo", "version", "min_vizi",
                "sdk_version", "asset_url", "sha256"]
KNOWN_PERMISSIONS = {"data_access", "contribute_rois"}  # §5 of the manifest schema
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^\d+(\.\d+)*[0-9a-z.]*$")  # 0.9.4, 1.0a83, 0.1.1
_CHUNK = 1 << 16


def download(url: str) -> tuple[str, int]:
    """Return (sha256_hex, size_bytes) for the bytes at url, streamed."""
    h = hashlib.sha256()
    n = 0
    req = urllib.request.Request(url, headers={"User-Agent": "vizi-verify-plugins"})
    with urllib.request.urlopen(req, timeout=60) as r:  # follows redirects
        while chunk := r.read(_CHUNK):
            h.update(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def validate_entry(p: dict, errs: list[str]) -> None:
    where = f"plugin '{p.get('id', '?')}'"
    for k in REQUIRED_STR:
        if not isinstance(p.get(k), str) or not p[k].strip():
            errs.append(f"{where}: '{k}' must be a non-empty string")
    if not isinstance(p.get("size"), int) or isinstance(p.get("size"), bool) or p.get("size", 0) <= 0:
        errs.append(f"{where}: 'size' must be a positive integer (bytes)")
    sha = p.get("sha256")
    if isinstance(sha, str) and not SHA256_RE.match(sha):
        errs.append(f"{where}: 'sha256' must be 64 lowercase hex characters")
    for key in ("repo", "asset_url"):
        v = p.get(key)
        if isinstance(v, str) and not v.startswith("https://"):
            errs.append(f"{where}: '{key}' must be an https:// URL")
    mv = p.get("min_vizi")
    if isinstance(mv, str) and not VERSION_RE.match(mv):
        errs.append(f"{where}: 'min_vizi' must look like a version, e.g. 0.9.4")
    perms = p.get("permissions")
    if not isinstance(perms, list) or not all(isinstance(x, str) for x in perms):
        errs.append(f"{where}: 'permissions' must be a list of strings")
    else:
        for x in perms:
            if x not in KNOWN_PERMISSIONS:
                print(f"  note: {where} declares permission '{x}' not known to this vizi "
                      f"(accepted, grants nothing) — confirm it is intentional")
    if "pending" in p and not isinstance(p["pending"], bool):
        errs.append(f"{where}: 'pending' must be true/false if present")


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the vizi plugin catalog.")
    ap.add_argument("--fetch", metavar="URL", help="download one asset; print its sha256 and size")
    args = ap.parse_args()

    if args.fetch:
        try:
            sha, size = download(args.fetch)
        except Exception as e:  # noqa: BLE001 — report any network/HTTP failure plainly
            return _fail(f"fetch failed: {e}")
        print(f"sha256: {sha}")
        print(f"size:   {size}")
        return 0

    data = yaml.safe_load(DATA.read_text())
    errs: list[str] = []
    if not isinstance(data, dict):
        return _fail(f"{DATA.name}: top level must be a mapping")
    if not isinstance(data.get("schema"), int) or isinstance(data.get("schema"), bool):
        errs.append("top-level 'schema' must be an integer")
    plugins = data.get("plugins")
    if not isinstance(plugins, list):
        errs.append("top-level 'plugins' must be a list")
        plugins = []

    ids = set()
    checked = live = 0
    for p in plugins:
        if not isinstance(p, dict):
            errs.append(f"each plugin must be a mapping; got {type(p).__name__}")
            continue
        validate_entry(p, errs)
        pid = p.get("id")
        if pid in ids:
            errs.append(f"duplicate id '{pid}'")
        ids.add(pid)

        if p.get("pending"):
            print(f"  {pid}: PENDING — shape checked; asset not fetched")
            continue
        live += 1
        # Live entry: the asset must exist and match byte-for-byte.
        try:
            sha, size = download(p["asset_url"])
        except Exception as e:  # noqa: BLE001
            errs.append(f"plugin '{pid}': could not fetch asset_url: {e}")
            continue
        checked += 1
        if size != p.get("size"):
            errs.append(f"plugin '{pid}': size {size} != declared {p.get('size')}")
        if sha != p.get("sha256"):
            errs.append(f"plugin '{pid}': sha256 {sha} != declared {p.get('sha256')}")
        if size == p.get("size") and sha == p.get("sha256"):
            print(f"  {pid}: OK — {size} bytes, sha256 {sha[:12]}…")

    if errs:
        print("\nFAILED:", file=sys.stderr)
        for e in errs:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print(f"\nOK — {len(plugins)} entr{'y' if len(plugins)==1 else 'ies'} "
          f"({live} live, {checked} asset(s) verified).")
    return 0


def _fail(msg: str) -> int:
    print(f"verify-plugins: {msg}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

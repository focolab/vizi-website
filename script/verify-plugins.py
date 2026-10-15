#!/usr/bin/env python3
"""Verify the accepted-plugin catalog (_data/plugins.yml).

Two uses:

  python script/verify-plugins.py
      Validate the shape of every entry, and for every LIVE (non-pending)
      entry re-download its asset_url, check the byte size and sha256, and
      read the plugin's vizi-plugin.json out of that same zip to check
      min_vizi against the manifest's protocol (engines.vizi). Exits non-zero
      on any problem. Run this when accepting a version, and gate it in CI.

  python script/verify-plugins.py --fetch <asset_url>
      Download one asset and print its sha256 and size, to paste into a new
      entry. (Does not touch the catalog.)

Only depends on the standard library plus PyYAML (`pip install pyyaml`).
The field contract it enforces is the one frozen in _data/plugins.yml.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tempfile
import urllib.request
import zipfile
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
KNOWN_PLATFORMS = {"linux-x86_64", "macos-arm64", "windows-x86_64"}
# A manifest's engines.vizi is the plugin PROTOCOL version, not the app version.
# Protocol 1.0 is served by vizi 0.9.0+, but the catalog-aware client (in-app
# install + platform/min_vizi filter) ships in 0.9.5 — so a cataloged protocol-1.0
# plugin must declare an app floor of at least 0.9.5. We CHECK min_vizi against
# this; we do not derive it (protocol version != app version).
APP_FLOOR_FOR_PROTOCOL_1 = (0, 9, 5)
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
VERSION_RE = re.compile(r"^\d+(\.\d+)*[0-9a-z.]*$")
_CHUNK = 1 << 16


def download(url: str, dest: Path) -> tuple[str, int]:
    """Stream url to dest; return (sha256_hex, size_bytes)."""
    h = hashlib.sha256()
    n = 0
    req = urllib.request.Request(url, headers={"User-Agent": "vizi-verify-plugins"})
    with urllib.request.urlopen(req, timeout=120) as r, open(dest, "wb") as f:  # follows redirects
        while chunk := r.read(_CHUNK):
            h.update(chunk)
            f.write(chunk)
            n += len(chunk)
    return h.hexdigest(), n


def version_tuple(s: str) -> tuple[int, ...]:
    """Leading dotted-integer version as a tuple, e.g. '0.9.5' -> (0, 9, 5)."""
    m = re.match(r"\d+(?:\.\d+)*", s or "")
    parts = tuple(int(x) for x in m.group(0).split(".")) if m else ()
    return parts + (0,) * (3 - len(parts)) if len(parts) < 3 else parts


def manifest_engines(zip_path: Path) -> tuple[str | None, str | None]:
    """Return (engines.vizi string, manifest path) from the plugin's
    vizi-plugin.json in the zip, or (None, None) if there isn't one.

    Per the vizi-plugin-sdk release contract, a release asset is one zip that
    unpacks to a single ``<plugin-id>/`` folder holding ``vizi-plugin.json``,
    so the shallowest manifest is the contract-correct one — this is the
    contract, not a guess.
    """
    with zipfile.ZipFile(zip_path) as z:
        cands = [n for n in z.namelist() if n.rsplit("/", 1)[-1] == "vizi-plugin.json"]
        if not cands:
            return None, None
        cands.sort(key=lambda n: (n.count("/"), len(n)))  # shallowest = the <plugin-id>/ root (release contract)
        raw = z.read(cands[0])
    try:
        return (json.loads(raw).get("engines") or {}).get("vizi"), cands[0]
    except (json.JSONDecodeError, AttributeError):
        return "", cands[0]  # present but unreadable


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
        errs.append(f"{where}: 'min_vizi' must look like a version, e.g. 0.9.5")
    perms = p.get("permissions")
    if not isinstance(perms, list) or not all(isinstance(x, str) for x in perms):
        errs.append(f"{where}: 'permissions' must be a list of strings")
    else:
        for x in perms:
            if x not in KNOWN_PERMISSIONS:
                print(f"  note: {where} declares permission '{x}' not known to this vizi "
                      f"(accepted, grants nothing) — confirm it is intentional")
    plats = p.get("platforms")
    if plats is not None:  # optional; absent means all three
        if not isinstance(plats, list) or not plats or not all(isinstance(x, str) for x in plats):
            errs.append(f"{where}: 'platforms', if present, must be a non-empty list of strings")
        else:
            bad = [x for x in plats if x not in KNOWN_PLATFORMS]
            if bad:
                errs.append(f"{where}: unknown platform(s) {bad}; allowed: {sorted(KNOWN_PLATFORMS)}")
            if len(set(plats)) != len(plats):
                errs.append(f"{where}: duplicate value in 'platforms'")
    if "pending" in p and not isinstance(p["pending"], bool):
        errs.append(f"{where}: 'pending' must be true/false if present")


def check_min_vizi_vs_manifest(p: dict, zip_path: Path, errs: list[str]) -> None:
    """Read engines.vizi from the asset's manifest and check min_vizi against it."""
    where = f"plugin '{p.get('id', '?')}'"
    engines, path = manifest_engines(zip_path)
    if engines is None:
        errs.append(f"{where}: no vizi-plugin.json found in the asset — cannot check engines.vizi")
        return
    if not engines:
        errs.append(f"{where}: vizi-plugin.json in the asset has no readable engines.vizi")
        return
    proto = version_tuple(engines)  # protocol major.minor
    print(f"  {p.get('id')}: manifest engines.vizi = {engines} (from {path})")
    mv = p.get("min_vizi")
    if not isinstance(mv, str):
        return  # already reported as a missing required field
    if proto[:1] == (1,):  # protocol 1.x (the only protocol today is 1.0)
        if version_tuple(mv) < APP_FLOOR_FOR_PROTOCOL_1:
            floor = ".".join(map(str, APP_FLOOR_FOR_PROTOCOL_1))
            errs.append(f"{where}: manifest declares protocol {engines}, so min_vizi must be "
                        f">= {floor} (the catalog-aware client floor); got {mv}")
    else:
        print(f"  {p.get('id')}: note — no app-version floor rule defined for protocol {engines}; "
              f"min_vizi {mv} accepted as-is")


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the vizi plugin catalog.")
    ap.add_argument("--fetch", metavar="URL", help="download one asset; print its sha256 and size")
    args = ap.parse_args()

    if args.fetch:
        with tempfile.NamedTemporaryFile(delete=True) as tf:
            try:
                sha, size = download(args.fetch, Path(tf.name))
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
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tf:
            tmp = Path(tf.name)
        try:
            sha, size = download(p["asset_url"], tmp)
            checked += 1
            if size != p.get("size"):
                errs.append(f"plugin '{pid}': size {size} != declared {p.get('size')}")
            if sha != p.get("sha256"):
                errs.append(f"plugin '{pid}': sha256 {sha} != declared {p.get('sha256')}")
            if size == p.get("size") and sha == p.get("sha256"):
                print(f"  {pid}: OK — {size} bytes, sha256 {sha[:12]}…")
            check_min_vizi_vs_manifest(p, tmp, errs)
        except Exception as e:  # noqa: BLE001
            errs.append(f"plugin '{pid}': could not fetch/read asset_url: {e}")
        finally:
            tmp.unlink(missing_ok=True)

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

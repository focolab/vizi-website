#!/usr/bin/env python3
"""Verify the accepted-plugin catalog (_data/plugins.yml).

Three uses:

  python script/verify-plugins.py
      Validate the shape of every entry, and for every LIVE (non-pending)
      entry re-download its asset_url, check the byte size and sha256, and
      read the plugin's vizi-plugin.json out of that same zip to check
      min_vizi against the manifest's protocol (engines.vizi) and its
      `extensions` against the manifest's readers. Exits non-zero on any
      problem. Run this when accepting a version, and gate it in CI.

  python script/verify-plugins.py --fetch <asset_url>
      Download one asset and print its sha256 and size, to paste into a new
      entry. (Does not touch the catalog.)

  python script/verify-plugins.py --selftest
      Run the offline unit checks for the extensions logic (normalisation, the
      manifest read, and the accept/reject matrix) and exit. No network, and
      standard library only — CI runs this on every trigger, before anything
      that needs PyYAML or the network.

The catalog check needs PyYAML (`pip install pyyaml`); --fetch and --selftest
use only the standard library. The field contract it enforces is the one frozen
in _data/plugins.yml.

Reader formats — the optional `extensions` field (vizi#1031)
------------------------------------------------------------
A plugin that opens file formats lists their suffixes in `extensions`, copied
from the asset manifest's ``contributions.readers[].extensions`` at acceptance
(the primary list, not ``fallback_extensions``), normalised to lower case with
one leading dot, de-duplicated and sorted. For a live entry the check reads
those suffixes out of the same zip it reads ``engines.vizi`` from and requires
the entry's `extensions` to equal them as a set; a manifest that declares reader
formats while the entry omits `extensions` is an error (acceptance forgot to
copy them).

Dry example (the catalog is empty live, so this documents the check):

    entry:    extensions: [".crate"]
    manifest: {"contributions": {"readers":
                [{"id": "crate", "extensions": [".crate"]}]}}

  Accepted — the sets match. Rejected: the entry drops `extensions` while the
  manifest declares ``.crate``; the entry lists [".crate", ".zip"] but the
  manifest has only ``.crate``; the entry lists [".CRATE"] (not lower case).
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

# PyYAML is imported lazily in main(), only for the catalog check — so --selftest
# and --fetch stay standard-library only (and runnable in CI before pip install).

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


def normalize_ext(s: str) -> str:
    """Normalise a reader suffix the way the SDK manifest schema does (readers
    §3.1): lower case with exactly one leading dot. 'TIF', '.tif' and 'tif' all
    become '.tif'; a compound suffix like '.ome.tif' keeps its inner dot."""
    return "." + s.strip().lower().lstrip(".")


def manifest_reader_extensions(zip_path: Path) -> set[str] | None:
    """Normalised set of file suffixes the asset's readers declare.

    Reads ``contributions.readers[].extensions`` from the plugin's
    vizi-plugin.json — each reader's PRIMARY extensions list, NOT
    ``fallback_extensions`` — and normalises every suffix. Returns the set
    (empty if no reader declares a format), or None when there is no readable
    manifest (the engines check reports that case)."""
    with zipfile.ZipFile(zip_path) as z:
        cands = [n for n in z.namelist() if n.rsplit("/", 1)[-1] == "vizi-plugin.json"]
        if not cands:
            return None
        cands.sort(key=lambda n: (n.count("/"), len(n)))  # shallowest = <plugin-id>/ root
        raw = z.read(cands[0])
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    readers = (data.get("contributions") or {}).get("readers")
    if not isinstance(readers, list):
        return set()
    exts: set[str] = set()
    for r in readers:
        if not isinstance(r, dict):
            continue
        for s in r.get("extensions") or []:
            if isinstance(s, str) and s.strip().strip("."):
                exts.add(normalize_ext(s))
    return exts


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
    exts = p.get("extensions")
    if exts is not None:  # optional; absent or empty means no formats offered on open
        if not isinstance(exts, list) or not exts or not all(isinstance(x, str) for x in exts):
            errs.append(f"{where}: 'extensions', if present, must be a non-empty list of strings")
        else:
            bad = [x for x in exts if not (x.startswith(".") and len(x) > 1 and x == x.lower())]
            if bad:
                errs.append(f"{where}: each extension must be lowercase with a leading dot, "
                            f"e.g. '.czi'; bad: {bad}")
            if len(set(exts)) != len(exts):
                errs.append(f"{where}: duplicate value in 'extensions'")
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


def check_extensions_vs_manifest(p: dict, zip_path: Path, errs: list[str]) -> None:
    """Require the entry's 'extensions' to equal the asset's declared reader
    suffixes (contributions.readers[].extensions), as a set."""
    where = f"plugin '{p.get('id', '?')}'"
    declared = manifest_reader_extensions(zip_path)
    if declared is None:
        return  # no readable manifest — the engines check reports that
    cat = p.get("extensions")
    if cat is None:
        if declared:
            errs.append(f"{where}: the asset's manifest declares reader formats "
                        f"{sorted(declared)} but the entry has no 'extensions' "
                        f"(copy them from the manifest at acceptance)")
        return
    if not isinstance(cat, list):
        return  # shape already reported by validate_entry
    catset = {x for x in cat if isinstance(x, str)}
    if catset == declared:
        print(f"  {p.get('id')}: extensions match manifest ({sorted(declared) or 'none'})")
        return
    bits = []
    extra = sorted(catset - declared)
    missing = sorted(declared - catset)
    if extra:
        bits.append(f"in entry but not the manifest: {extra}")
    if missing:
        bits.append(f"in the manifest but not the entry: {missing}")
    errs.append(f"{where}: 'extensions' does not match the asset's reader formats "
                f"(entry {sorted(catset)} vs manifest {sorted(declared)}; {'; '.join(bits)})")


def selftest() -> int:
    """Offline checks for the `extensions` logic — no network, stdlib only.

    Covers suffix normalisation, reading reader extensions out of a crafted zip
    (fallback_extensions and a deeper manifest both excluded, mixed case
    de-duplicated), and the accept/reject matrix against a fully-valid entry so
    only extension problems surface."""
    failures: list[str] = []

    def check(name: str, ok: bool) -> None:
        print(f"  {'ok  ' if ok else 'FAIL'} {name}")
        if not ok:
            failures.append(name)

    for raw, want in [("TIF", ".tif"), (".tif", ".tif"), ("tif", ".tif"),
                      (".ome.tif", ".ome.tif"), ("  .CZI ", ".czi"), ("..x", ".x")]:
        check(f"normalize_ext({raw!r}) == {want!r}", normalize_ext(raw) == want)

    with tempfile.TemporaryDirectory() as td:
        zpath = Path(td) / "plugin.zip"
        manifest = {"contributions": {"readers": [
            {"id": "a", "extensions": [".czi", "CZI"]},
            {"id": "b", "extensions": [".lif"], "fallback_extensions": [".h5"]},
        ]}}
        with zipfile.ZipFile(zpath, "w") as z:
            z.writestr("myplugin/vizi-plugin.json", json.dumps(manifest))
            z.writestr("myplugin/nested/vizi-plugin.json", json.dumps(
                {"contributions": {"readers": [{"id": "x", "extensions": [".deep"]}]}}))
        check("manifest read = {.czi,.lif} (fallback + deeper manifest excluded, "
              "mixed case de-duplicated)", manifest_reader_extensions(zpath) == {".czi", ".lif"})

        znone = Path(td) / "noreaders.zip"
        with zipfile.ZipFile(znone, "w") as z:
            z.writestr("p/vizi-plugin.json", json.dumps({"contributions": {"commands": []}}))
        check("no readers -> empty set", manifest_reader_extensions(znone) == set())

        base = {"id": "org.example.p", "name": "P", "summary": "s",
                "repo": "https://example.com/p", "version": "1.0.0", "min_vizi": "0.9.5",
                "sdk_version": "1.0.0", "asset_url": "https://example.com/p.zip",
                "size": 10, "sha256": "a" * 64, "permissions": []}

        def errs_for(*, extensions="\0absent"):
            entry = dict(base)
            if extensions != "\0absent":
                entry["extensions"] = extensions
            out: list[str] = []
            validate_entry(entry, out)
            check_extensions_vs_manifest(entry, zpath, out)
            return out

        check("match accepts", errs_for(extensions=[".czi", ".lif"]) == [])
        check("missing field rejected",
              any("has no 'extensions'" in e for e in errs_for()))
        check("superset rejected",
              any("does not match" in e and ".zip" in e for e in errs_for(extensions=[".czi", ".lif", ".zip"])))
        check("uppercase rejected",
              any("lowercase with a leading dot" in e for e in errs_for(extensions=[".CZI", ".lif"])))
        check("no-dot rejected",
              any("lowercase with a leading dot" in e for e in errs_for(extensions=["czi"])))
        check("duplicate rejected",
              any("duplicate value in 'extensions'" in e for e in errs_for(extensions=[".czi", ".czi", ".lif"])))
        check("empty list rejected",
              any("non-empty list" in e for e in errs_for(extensions=[])))

    if failures:
        print(f"\nSELFTEST FAILED: {len(failures)} case(s)", file=sys.stderr)
        return 1
    print("\nselftest OK")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify the vizi plugin catalog.")
    ap.add_argument("--fetch", metavar="URL", help="download one asset; print its sha256 and size")
    ap.add_argument("--selftest", action="store_true",
                    help="run offline unit checks (no network, stdlib only) and exit")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    if args.fetch:
        with tempfile.NamedTemporaryFile(delete=True) as tf:
            try:
                sha, size = download(args.fetch, Path(tf.name))
            except Exception as e:  # noqa: BLE001 — report any network/HTTP failure plainly
                return _fail(f"fetch failed: {e}")
            print(f"sha256: {sha}")
            print(f"size:   {size}")
        return 0

    try:
        import yaml
    except ImportError:
        return _fail("the catalog check needs PyYAML — `pip install pyyaml`")
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
            check_extensions_vs_manifest(p, tmp, errs)
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

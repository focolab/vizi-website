#!/usr/bin/env python3
"""
Local preview for the vizi-website Jekyll site without installing Ruby/Jekyll.

Resolves the minimal Liquid templating used in index.html, compiles the SCSS
with libsass, mirrors the file tree into _preview/, and serves it.

Run: python3 preview.py  (then open http://localhost:8000)
"""
import datetime
import http.server
import os
import re
import shutil
import socketserver
import sys
from pathlib import Path

import sass

ROOT = Path(__file__).parent
OUT = ROOT / "_preview"
PORT = 8000

SITE = {
    "url": "",
    "baseurl": "",
    "title": "vizi",
    "description": (
        "High-performance visualization of 2D/3D/4D/5D scientific imaging "
        "data in the era of AI."
    ),
}


def resolve_liquid(text: str) -> str:
    """Resolve the limited Liquid we use: site.* lookups, relative_url, date 'now'."""

    def repl(match: re.Match) -> str:
        expr = match.group(1).strip()

        # {{ 'now' | date: '%Y' }}
        m = re.match(r"'now'\s*\|\s*date:\s*'([^']+)'", expr)
        if m:
            return datetime.datetime.now().strftime(m.group(1))

        # {{ 'literal' | relative_url }}
        m = re.match(r"'([^']+)'\s*\|\s*relative_url", expr)
        if m:
            return SITE["baseurl"] + m.group(1)

        # {{ site.foo | relative_url }} or {{ site.foo }}
        m = re.match(r"site\.(\w+)(?:\s*\|\s*relative_url)?", expr)
        if m:
            val = SITE.get(m.group(1), "")
            if "relative_url" in expr:
                return SITE["baseurl"] + val
            return val

        return match.group(0)

    return re.sub(r"\{\{\s*(.*?)\s*\}\}", repl, text)


def build():
    # Clear contents in place rather than rmtree the directory itself,
    # so a running http.server's cwd stays valid across rebuilds.
    OUT.mkdir(exist_ok=True)
    for child in OUT.iterdir():
        if child.is_dir():
            shutil.rmtree(child)
        else:
            child.unlink()

    # Copy static assets verbatim, skipping SCSS (compiled separately) and dotfiles.
    for src in ROOT.rglob("*"):
        if src.is_dir():
            continue
        rel = src.relative_to(ROOT)
        parts = rel.parts
        if any(p.startswith(".") for p in parts):
            continue
        if parts[0] in {"_preview", "_site", "vendor", "__pycache__"}:
            continue
        if src.name in {"preview.py", "_config.yml", "Gemfile", "Gemfile.lock", "CNAME", "README.md"}:
            continue
        if src.suffix == ".scss":
            continue
        if src.suffix in {".html", ".md"}:
            text = src.read_text(encoding="utf-8")
            # Strip Jekyll frontmatter if present.
            if text.startswith("---"):
                end = text.find("\n---", 3)
                if end != -1:
                    text = text[end + 4 :].lstrip("\n")
            text = resolve_liquid(text)
            dest = OUT / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(text, encoding="utf-8")
        else:
            dest = OUT / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dest)

    # Compile SCSS files (strip frontmatter, then sass.compile).
    for scss in ROOT.rglob("*.scss"):
        if "_preview" in scss.parts or "_site" in scss.parts:
            continue
        text = scss.read_text(encoding="utf-8")
        if text.startswith("---"):
            end = text.find("\n---", 3)
            if end != -1:
                text = text[end + 4 :].lstrip("\n")
        css = sass.compile(string=text, output_style="expanded")
        rel = scss.relative_to(ROOT).with_suffix(".css")
        dest = OUT / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(css, encoding="utf-8")

    print(f"Built into {OUT}")


def serve():
    os.chdir(OUT)
    handler = http.server.SimpleHTTPRequestHandler
    with socketserver.TCPServer(("", PORT), handler) as httpd:
        print(f"Serving at http://localhost:{PORT}  (Ctrl+C to stop)")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")


if __name__ == "__main__":
    build()
    if "--build-only" not in sys.argv:
        serve()

#!/usr/bin/env python3
"""Fail-closed, dependency-free verifier for one public GitHub Pages preview.

The manifest is an integrity record, not a privacy certificate. Audit the export
before uploading it: the ZIP itself is public once committed to the repository.
This program never executes archive contents and never contacts a network.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import struct
import sys
import zipfile
from html.parser import HTMLParser
from urllib.parse import unquote, urlsplit

FORMAT = "portfolio-public-pages-v1"
BASE_PATH = "/portfolio-public/"
ORIGIN = "https://masudrabbani.github.io"
LIVE_ORIGIN = "https://masudrabbani.com"
OWNER_URL = "https://masud-rabbani-staging.masud-rabbani-bg.workers.dev/admin"
PRODUCTION_ROBOTS = "User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api\nSitemap: https://masudrabbani.com/sitemap.xml\n"
INDEXNOW_KEY = "178f6702794fd56ec0a71adaab9b6ec2c9d100f6d27b31e12d047d00678e86fc"
MAX_ARCHIVE_BYTES = 32 * 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_FILE_BYTES = 25 * 1024 * 1024
MAX_FILES = 5000
MAX_COMPRESSION_RATIO = 200
CHUNK_BYTES = 64 * 1024

PUBLIC_EXTENSIONS = frozenset({
    ".html", ".rsc", ".js", ".css", ".svg", ".xml", ".xsl", ".json",
    ".txt", ".bib", ".ris", ".pdf", ".docx", ".png", ".jpg", ".jpeg",
    ".gif", ".webp", ".ico",
})
TEXT_EXTENSIONS = PUBLIC_EXTENSIONS - {
    ".pdf", ".docx", ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico",
}
BLOCKED_SEGMENTS = frozenset({
    "admin", "api", "auth", "private", "backup", "backups", "private-backups",
    "node_modules", "server", "src", "scripts", "drizzle", "db", "database",
    "credentials", "secrets", "work", "__releases",
})
BLOCKED_FILENAMES = frozenset({
    "cname", "package.json", "package-lock.json", "tsconfig.json", "wrangler.json",
    "wrangler.jsonc", "database.json", "inventory.json", "inventory-after.json",
    "release-manifest.json", "public-manifest.json", "public-snapshot.json",
    "verification.json", "config.json", "composer.json", "manifest.webmanifest",
})
SECRET_MARKERS = re.compile(
    r"(?:/Users/|/private/tmp/|OWNER_SESSION_SECRET|GITHUB_CLIENT_SECRET|"
    r"CLOUDFLARE_API_TOKEN|STAGING_CLOUD_DEPLOY_HOOK|lease_token|"
    r"database\.json|-----BEGIN (?:[A-Z ]+ )?PRIVATE KEY-----|"
    r"github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"api\.cloudflare\.com/client/v4/workers/builds/deploy_hooks/|"
    r"/api/admin(?:[/\"'?#]|$)|sourceMappingURL=)",
    re.IGNORECASE,
)
TRACKING_MARKERS = re.compile(
    r"googletagmanager\.com|google-analytics\.com|G-5K4CVPJ8KX", re.IGNORECASE
)


class Rejected(ValueError):
    """A fixed diagnostic code; never include content or credentials in errors."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise Rejected(code)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def legacy_alias_kind(path: str) -> str | None:
    if path == "admin/index.html":
        return "admin"
    if re.fullmatch(r"api/cv/(?:pdf|docx)/index\.html", path):
        return "cv"
    if re.fullmatch(r"api/publications/[A-Za-z0-9_-]{1,180}/citation/index\.html", path):
        return "citation"
    if re.fullmatch(r"api/blog/media/[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}\.(?:png|jpg|webp)", path):
        return "media"
    return None


def checked_path(value: object, production: bool = False) -> str:
    require(isinstance(value, str), "invalid-path")
    require(0 < len(value) <= 240 and value.isascii(), "invalid-path")
    require(not value.startswith("/") and not value.endswith("/"), "invalid-path")
    require(re.fullmatch(r"[A-Za-z0-9_./-]+", value) is not None, "invalid-path")
    parts = value.split("/")
    require(all(part and part not in {".", ".."} and len(part) <= 180 for part in parts), "invalid-path")
    if value == ".nojekyll":
        return value
    require(not any(part.startswith(".") for part in parts), "hidden-file")
    require(production and legacy_alias_kind(value) is not None
            or not any(part.lower() in BLOCKED_SEGMENTS for part in parts), "private-path")
    require(parts[-1].lower() not in BLOCKED_FILENAMES, "private-file")
    require(Path(value).suffix.lower() in PUBLIC_EXTENSIONS, "unsupported-file-type")
    require(not re.search(r"(?:^|[._-])(?:backup|secret|credential|token|private)(?:[._-]|$)", parts[-1], re.I), "private-file")
    return value


def no_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate-json-key")
        result[key] = value
    return result


def parse_manifest(data: bytes) -> dict[str, dict]:
    require(len(data) <= MAX_MANIFEST_BYTES, "manifest-size")
    try:
        manifest = json.loads(data.decode("utf-8"), object_pairs_hook=no_duplicate_keys)
    except Rejected:
        raise
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise Rejected("invalid-manifest") from None
    require(isinstance(manifest, dict) and set(manifest) == {
        "format", "basePath", "origin", "archiveSha256", "files"
    }, "manifest-fields")
    require(manifest["format"] == FORMAT and (manifest["basePath"], manifest["origin"]) in {
        (BASE_PATH, ORIGIN), ("/", LIVE_ORIGIN)}, "manifest-target")
    production = manifest["origin"] == LIVE_ORIGIN
    require(isinstance(manifest["archiveSha256"], str)
            and re.fullmatch(r"[a-f0-9]{64}", manifest["archiveSha256"]) is not None, "archive-digest")
    records = manifest["files"]
    require(isinstance(records, list) and 0 < len(records) <= MAX_FILES, "file-count")
    files = {}
    folded = set()
    total = 0
    for record in records:
        require(isinstance(record, dict) and set(record) == {"path", "bytes", "sha256"}, "file-fields")
        path = checked_path(record["path"], production)
        require(path.casefold() not in folded, "duplicate-path")
        require(type(record["bytes"]) is int and 0 <= record["bytes"] <= MAX_FILE_BYTES, "file-size")
        require(isinstance(record["sha256"], str)
                and re.fullmatch(r"[a-f0-9]{64}", record["sha256"]) is not None, "file-digest")
        if path == ".nojekyll":
            require(record["bytes"] == 0, "nonempty-nojekyll")
        total += record["bytes"]
        require(total <= MAX_TOTAL_BYTES, "total-size")
        files[path] = record
        folded.add(path.casefold())
    require("index.html" in files and "robots.txt" in files, "missing-preview-entrypoints")
    for path in files:
        segments = path.split("/")
        require(not any("/".join(segments[:index]).casefold() in folded
                        for index in range(1, len(segments))), "file-directory-collision")
    return manifest


class PageAudit(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.robots = []
        self.canonicals = []
        self.dependencies = []

    def handle_starttag(self, tag: str, attributes: list[tuple[str, str | None]]) -> None:
        attrs = dict(attributes)
        if tag == "meta" and (attrs.get("name") or "").lower() in {"robots", "googlebot"}:
            self.robots.append(attrs.get("content") or "")
        if tag == "link":
            relations = (attrs.get("rel") or "").lower().split()
            if "canonical" in relations:
                self.canonicals.append(attrs.get("href") or "")
            if any(rel in {"stylesheet", "preload", "modulepreload", "icon"} for rel in relations):
                self.dependencies.append(attrs.get("href") or "")
        if tag in {"img", "script", "source", "video", "audio", "iframe", "embed"} and "src" in attrs:
            self.dependencies.append(attrs.get("src") or "")
        if tag in {"img", "source"} and attrs.get("srcset"):
            # The current exporter emits ordinary src, not srcset/data-URI sets.
            for candidate in attrs["srcset"].split(","):
                self.dependencies.append(candidate.strip().split(" ")[0])


def audit_dependency(url: str, files: dict[str, dict], production: bool = False) -> None:
    if re.match(r"^data:image/(?:png|jpeg|gif|webp);base64,[A-Za-z0-9+/=]+$", url):
        return
    try:
        parts = urlsplit(url)
        origin, base = (LIVE_ORIGIN, "/") if production else (ORIGIN, BASE_PATH)
        require(not parts.netloc or f"{parts.scheme}://{parts.netloc}" == origin, "external-preview-dependency")
        require(not parts.scheme or parts.scheme == "https", "external-preview-dependency")
        require(parts.path.startswith(base) and not parts.path.startswith("//"), "incorrect-preview-prefix")
        path = unquote(parts.path[len(base):], errors="strict")
        require("%" not in path and "\\" not in path and not any(p in {".", ".."} for p in path.split("/")), "unsafe-dependency")
        require(path in files or path + "index.html" in files or path.rstrip("/") + "/index.html" in files, "missing-preview-dependency")
    except (UnicodeDecodeError, ValueError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("unsafe-dependency") from None


def redirect_page(url: str) -> bytes:
    canonical = LIVE_ORIGIN + url if url.startswith("/") else url
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex, nofollow, noarchive"><meta http-equiv="refresh" content="0;url={url}"><link rel="canonical" href="{canonical}"><title>Continue</title></head><body><p><a href="{url}">Continue</a></p></body></html>\n').encode()


def citation_page(identifier: str) -> bytes:
    return (f'<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="robots" content="noindex, nofollow, noarchive"><link rel="canonical" href="{LIVE_ORIGIN}/publications/{identifier}"><title>Download citation</title></head><body><p><a href="/citations/{identifier}.bib">BibTeX</a> <a href="/citations/{identifier}.ris">RIS</a></p><script>location.replace(new URLSearchParams(location.search).get("format")==="ris"?"/citations/{identifier}.ris":"/citations/{identifier}.bib");</script></body></html>\n').encode()


def production_indexable(files: dict[str, bytes]) -> set[str]:
    require("sitemap.xml" in files and "blog/feed.xml" in files, "production-discovery")
    text = files["sitemap.xml"].decode("utf-8")
    require(not re.search(r"<!DOCTYPE|<!ENTITY", text, re.I), "unsafe-sitemap")
    result = set()
    for location in re.findall(r"<loc>([^<]+)</loc>", text):
        parts = urlsplit(location)
        require(f"{parts.scheme}://{parts.netloc}" == LIVE_ORIGIN and not parts.query and not parts.fragment,
                "sitemap-url")
        path = unquote(parts.path, errors="strict").removeprefix("/").removesuffix("/")
        require(not re.search(r"[\\\x00-\x1f]", path) and not any(p in {".", ".."} for p in path.split("/")), "sitemap-path")
        file = path + "/index.html" if path else "index.html"
        require(file in files and file not in result and legacy_alias_kind(file) is None and file != "404.html", "sitemap-entry")
        result.add(file)
    require("index.html" in result, "sitemap-home")
    return result


def audit_content(path: str, data: bytes, files: dict[str, dict], production: bool = False,
                  indexable: set[str] | None = None, content: dict[str, bytes] | None = None) -> None:
    if path == ".nojekyll":
        require(data == b"", "nonempty-nojekyll")
        return
    extension = Path(path).suffix.lower()
    if extension in TEXT_EXTENSIONS:
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            raise Rejected("invalid-text-encoding") from None
        require("\x00" not in text, "binary-text")
        require(not SECRET_MARKERS.search(text), "private-content-marker")
        if not production:
            require(not TRACKING_MARKERS.search(text), "preview-tracking-marker")
        else:
            require(ORIGIN + BASE_PATH not in text and "Analytics is disabled on this test preview." not in text, "preview-residue")
            if TRACKING_MARKERS.search(text):
                require(re.fullmatch(r"cached-static/.+/regional-google-analytics-[^/]+\.js", path) is not None
                        and "google-analytics.com" not in text
                        and all(value == "G-5K4CVPJ8KX" for value in re.findall(r"G-[A-Z0-9]{6,}", text)), "production-tracking-scope")
        if extension == ".html":
            audit = PageAudit()
            try:
                audit.feed(text)
                audit.close()
            except Exception:
                raise Rejected("invalid-html") from None
            require(bool(audit.robots), "missing-index-policy")
            for value in audit.robots:
                policy = {part.strip().lower() for part in value.split(",")}
                if not production:
                    require(policy == {"noindex", "nofollow", "noarchive"}, "preview-index-policy")
                elif path in (indexable or set()):
                    require({"index", "follow"} <= policy and not {"noindex", "nofollow"} & policy, "production-index-policy")
                else:
                    require("noindex" in policy and "index" not in policy, "production-index-policy")
            require(all((production and path == "admin/index.html" and url == OWNER_URL)
                        or url == LIVE_ORIGIN or url.startswith(LIVE_ORIGIN + "/")
                        for url in audit.canonicals), "changed-live-canonical")
            for url in audit.dependencies:
                audit_dependency(url, files, production)
        if path == "robots.txt":
            require(text == PRODUCTION_ROBOTS if production else text.replace("\r\n", "\n").strip() == "User-agent: *\nDisallow: /", "robots-policy")
        if production and path == "indexnow-verification.txt":
            require(text == INDEXNOW_KEY, "indexnow-key")
    else:
        signatures = {
            ".pdf": data.startswith(b"%PDF-"),
            ".docx": data.startswith(b"PK\x03\x04"),
            ".png": data.startswith(b"\x89PNG\r\n\x1a\n"),
            ".jpg": data.startswith(b"\xff\xd8\xff"),
            ".jpeg": data.startswith(b"\xff\xd8\xff"),
            ".gif": data.startswith((b"GIF87a", b"GIF89a")),
            ".webp": data.startswith(b"RIFF") and data[8:12] == b"WEBP",
            ".ico": data.startswith(b"\x00\x00\x01\x00"),
        }
        require(signatures.get(extension, False), "binary-signature")
    alias = legacy_alias_kind(path) if production else None
    if alias == "admin":
        require(data == redirect_page(OWNER_URL), "admin-handoff")
    elif alias == "cv":
        target = f"downloads/Masud-Rabbani-Academic-CV.{path.split('/')[2]}"
        require(target in files and data == redirect_page("/" + target), "cv-alias")
    elif alias == "citation":
        identifier = path.split("/")[2]
        require(f"citations/{identifier}.bib" in files and f"citations/{identifier}.ris" in files
                and data == citation_page(identifier), "citation-alias")
    elif alias == "media":
        require(content is not None and content.get("media/blog/" + path.removeprefix("api/blog/media/")) == data, "media-alias-integrity")


def verify_archive(archive_bytes: bytes, manifest_bytes: bytes) -> dict[str, bytes]:
    """Return verified bytes only after every entry passes. Never extract blindly."""
    require(22 <= len(archive_bytes) <= MAX_ARCHIVE_BYTES, "archive-size")
    manifest = parse_manifest(manifest_bytes)
    production = manifest["origin"] == LIVE_ORIGIN
    require(sha256(archive_bytes) == manifest["archiveSha256"], "archive-hash-mismatch")
    # No prepended executable, trailing data, ZIP64, split archive, or comments.
    require(archive_bytes.startswith(b"PK\x03\x04") and archive_bytes[-22:-18] == b"PK\x05\x06", "zip-envelope")
    disk, central_disk, disk_entries, entries, central_size, central_offset, comment = struct.unpack(
        "<4H2IH", archive_bytes[-18:]
    )
    require(disk == central_disk == comment == 0 and disk_entries == entries
            and 0 < entries <= MAX_FILES and central_offset + central_size == len(archive_bytes) - 22, "zip-envelope")
    expected = {record["path"]: record for record in manifest["files"]}
    verified = {}
    try:
        with zipfile.ZipFile(io.BytesIO(archive_bytes)) as archive:
            items = archive.infolist()
            require(len(items) == entries == len(expected) and not archive.comment, "archive-inventory")
            for item in items:
                path = checked_path(item.orig_filename, production)
                require(item.filename == item.orig_filename and path in expected and path not in verified, "archive-inventory")
                mode = item.external_attr >> 16
                require(not item.is_dir() and (stat.S_IFMT(mode) in {0, stat.S_IFREG})
                        and not (mode & (stat.S_ISUID | stat.S_ISGID | stat.S_ISVTX))
                        and not (item.external_attr & 0x10), "linked-or-special-entry")
                require(not item.comment and not item.extra and item.create_system in {0, 3}, "unsupported-zip-metadata")
                require(item.compress_type in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                        and not (item.flag_bits & ~0x80E), "unsupported-zip-format")
                require(0 <= item.header_offset < central_offset and item.file_size == expected[path]["bytes"], "file-size")
                require(item.file_size == 0 or (item.compress_size > 0
                        and item.file_size <= item.compress_size * MAX_COMPRESSION_RATIO), "compression-ratio")
                chunks = []
                size = 0
                with archive.open(item) as stream:
                    while chunk := stream.read(CHUNK_BYTES):
                        size += len(chunk)
                        require(size <= expected[path]["bytes"] and size <= MAX_FILE_BYTES, "expanded-size")
                        chunks.append(chunk)
                data = b"".join(chunks)
                require(size == expected[path]["bytes"] and sha256(data) == expected[path]["sha256"], "file-hash-mismatch")
                verified[path] = data
            require(set(verified) == set(expected), "archive-inventory")
    except Rejected:
        raise
    except (zipfile.BadZipFile, RuntimeError, NotImplementedError, EOFError, OSError, ValueError):
        raise Rejected("invalid-archive") from None
    indexable = production_indexable(verified) if production else None
    for path, data in verified.items():
        audit_content(path, data, expected, production, indexable, verified)
    return verified


def read_regular_file(path: Path, maximum: int) -> bytes:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        info = os.fstat(descriptor)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_size <= maximum, "unsafe-input-file")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            data = stream.read(maximum + 1)
        require(len(data) <= maximum, "input-size")
        return data
    finally:
        os.close(descriptor)


def publish_directory(root: Path) -> tuple[int, int]:
    """Fixed filenames/output only. Refuse to overwrite an existing directory."""
    require(root.is_dir() and root.resolve() == root, "unsafe-working-directory")
    archive = read_regular_file(root / "static-public.zip", MAX_ARCHIVE_BYTES)
    manifest = read_regular_file(root / "public-manifest.json", MAX_MANIFEST_BYTES)
    verified = verify_archive(archive, manifest)
    output = root / "_site"
    require(not os.path.lexists(output), "output-already-exists")
    output.mkdir(mode=0o755)
    for path, data in verified.items():
        target = output / path
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
        descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
    return len(verified), sum(map(len, verified.values()))


def main() -> int:
    try:
        require(len(sys.argv) == 1, "arguments-not-supported")
        count, total = publish_directory(Path.cwd().resolve())
    except Rejected as error:
        print(f"Public preview rejected: {error}.", file=sys.stderr)
        return 1
    except Exception:
        # Do not print file contents, URLs, provider errors, or arbitrary paths.
        print("Public preview rejected: input-or-output-failure.", file=sys.stderr)
        return 1
    print(f"Verified {count} public files ({total} bytes) for the isolated GitHub Pages preview.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build the compact 0x VPN hosts hash artifact and manifest."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import os
import re
import struct
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAGIC = b"VADBLK1\n"
SOURCE_FILES = (
    ("adaway.txt", "https://raw.githubusercontent.com/AdAway/adaway.github.io/master/hosts.txt"),
    ("yoyo.txt", "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext"),
    ("stevenblack.txt", "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts"),
    ("ublock-filters.txt", "https://ublockorigin.github.io/uAssets/filters/filters.txt"),
    ("ublock-badware.txt", "https://ublockorigin.github.io/uAssets/filters/badware.txt"),
    ("ublock-privacy.txt", "https://ublockorigin.github.io/uAssets/filters/privacy.txt"),
    ("ublock-quick-fixes.txt", "https://ublockorigin.github.io/uAssets/filters/quick-fixes.txt"),
    ("ublock-resource-abuse.txt", "https://ublockorigin.github.io/uAssets/filters/resource-abuse.txt"),
    ("easylist.txt", "https://easylist.to/easylist/easylist.txt"),
    ("easyprivacy.txt", "https://easylist.to/easylist/easyprivacy.txt"),
)
SOURCE_URLS = tuple(url for _, url in SOURCE_FILES)
EXPECTED_INPUT_NAMES = {name for name, _ in SOURCE_FILES}
FILTER_INPUT_NAMES = {
    "ublock-filters.txt",
    "ublock-badware.txt",
    "ublock-privacy.txt",
    "ublock-quick-fixes.txt",
    "ublock-resource-abuse.txt",
    "easylist.txt",
    "easyprivacy.txt",
}
MAX_INPUT_BYTES = 20 * 1024 * 1024
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
IGNORED_DOMAINS = {"localhost", "localhost.localdomain", "broadcasthost"}
COSMETIC_FILTER_MARKERS = ("##", "#@#", "#?#", "#$#", "#%#")
SAFE_FILTER_OPTIONS = {"3p", "third-party"}


def normalize_domain(value: str) -> str:
    domain = value.strip().rstrip(".").lower()
    try:
        domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return ""
    if not DOMAIN_RE.fullmatch(domain):
        return ""
    return domain


def is_ignored_domain(domain: str) -> bool:
    return not domain or domain in IGNORED_DOMAINS


def filter_options_are_dns_safe(options: str) -> bool:
    if not options:
        return True
    for raw_option in options.split(","):
        option = raw_option.strip().lower()
        if not option:
            continue
        option = option.lstrip("~")
        option = option.split("=", 1)[0]
        if option not in SAFE_FILTER_OPTIONS:
            return False
    return True


def parse_adblock_filter_line(value: str) -> str:
    line = value.strip()
    if not line or line.startswith(("!", "[", "@@")):
        return ""
    if any(marker in line for marker in COSMETIC_FILTER_MARKERS):
        return ""
    if "$" in line:
        line, options = line.split("$", 1)
        if not filter_options_are_dns_safe(options):
            return ""
        line = line.rstrip()
    match = re.fullmatch(r"\|\|([A-Za-z0-9._-]+)\^?", line)
    if not match:
        return ""
    domain = normalize_domain(match.group(1))
    return "" if is_ignored_domain(domain) else domain


def looks_like_adblock_filter_line(value: str) -> bool:
    line = value.strip()
    return (
        not line
        or line.startswith(("!", "[", "@@", "||", "|", "/"))
        or any(marker in line for marker in COSMETIC_FILTER_MARKERS)
    )


def parse_source_file(path: Path) -> set[str]:
    if not path.is_file():
        raise ValueError(f"input does not exist: {path}")
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_INPUT_BYTES:
        raise ValueError("input size is outside the allowed range")
    mode = "filter" if path.name in FILTER_INPUT_NAMES else ("hosts" if path.name in EXPECTED_INPUT_NAMES else "mixed")
    domains: set[str] = set()
    with path.open("r", encoding="utf-8", errors="strict") as source:
        for raw_line in source:
            stripped = raw_line.strip()
            if mode in {"filter", "mixed"}:
                filter_domain = parse_adblock_filter_line(stripped)
                if filter_domain:
                    domains.add(filter_domain)
                    continue
                if looks_like_adblock_filter_line(stripped):
                    continue
            if mode == "filter":
                continue
            line = stripped.split("#", 1)[0].strip()
            if not line:
                continue
            fields = line.split()
            candidates = fields[1:] if len(fields) > 1 else fields
            if len(fields) > 1:
                try:
                    ipaddress.ip_address(fields[0])
                except ValueError:
                    candidates = fields
            for candidate in candidates:
                domain = normalize_domain(candidate)
                if not is_ignored_domain(domain):
                    domains.add(domain)
    return domains


def parse_hosts(path: Path) -> tuple[set[str], str]:
    inputs = sorted(path.glob("*.txt")) if path.is_dir() else [path]
    if not inputs:
        raise ValueError("input directory contains no .txt files")
    if path.is_dir() and {item.name for item in inputs} != EXPECTED_INPUT_NAMES:
        expected = ", ".join(sorted(EXPECTED_INPUT_NAMES))
        raise ValueError(f"input directory must contain exactly: {expected}")
    domains: set[str] = set()
    source_digest = hashlib.sha256()
    for item in inputs:
        content = item.read_bytes()
        source_digest.update(item.name.encode("utf-8"))
        source_digest.update(b"\0")
        source_digest.update(hashlib.sha256(content).digest())
        domains.update(parse_source_file(item))
    return domains, source_digest.hexdigest()


def write_atomic(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=path.name + ".", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary_name, path)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except FileNotFoundError:
            pass
        raise


def build(input_path: Path, output_dir: Path, minimum: int, maximum: int, generated_at: str) -> tuple[int, str]:
    domains, source_digest = parse_hosts(input_path)
    if len(domains) < minimum or len(domains) > maximum:
        raise ValueError(f"domain count {len(domains)} is outside {minimum}..{maximum}")
    hashes = sorted({hashlib.sha256(domain.encode("ascii")).digest()[:16] for domain in domains})
    if len(hashes) != len(domains):
        raise ValueError("truncated hash collision detected")
    artifact = MAGIC + struct.pack(">I", len(hashes)) + b"".join(hashes)
    digest = hashlib.sha256(artifact).hexdigest()
    manifest = (
        "format=vantage-adblock-v1\n"
        "artifact=adaway.bin\n"
        f"entries={len(hashes)}\n"
        f"sha256={digest}\n"
        f"generatedAt={generated_at}\n"
        f"source={SOURCE_URLS[0]}\n"
        f"sources={'|'.join(SOURCE_URLS)}\n"
        f"sourceSha256={source_digest}\n"
    ).encode("ascii")
    write_atomic(output_dir / "adaway.bin", artifact)
    write_atomic(output_dir / "manifest.properties", manifest)
    return len(hashes), digest


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument("output_dir", type=Path)
    parser.add_argument("--min-domains", type=int, default=1_000)
    parser.add_argument("--max-domains", type=int, default=250_000)
    parser.add_argument("--generated-at", default=datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"))
    args = parser.parse_args()
    try:
        count, digest = build(args.input, args.output_dir, args.min_domains, args.max_domains, args.generated_at)
    except (OSError, UnicodeError, ValueError) as error:
        parser.error(str(error))
    print(f"entries={count}")
    print(f"sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
import asyncio
import os
import gzip
from datetime import datetime, timezone, timedelta
from typing import Iterator, Tuple, List

from czds import CZDS

USERNAME = os.environ.get("CZDS_USERNAME")
PASSWORD = os.environ.get("CZDS_PASSWORD")

TARGET_TLDS = {"com", "net", "org"}
ZONES_DIR = "zones"
TIMESTAMP_FILE = os.path.join(ZONES_DIR, "timestamp")
MAX_AGE = timedelta(days=7)

MAX_CONCURRENT_DOWNLOADS = 3

OUR_NS_DOMAINS = {
    "iinet.com",
    "easystreet.com",
    "nwlink.com",
    "pacifier.com",
    "tstonramp.com",
    "proaxis.com",
    "pacifier.net",
    "e-z.net",
    "inactive.net",
}


def is_our_nameserver(ns: str) -> bool:
    """
    Return True if the nameserver belongs to our infrastructure.
    """
    for allowed in OUR_NS_DOMAINS:
        if ns.endswith(allowed):
            return True

    return False


def open_zone(path: str):
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def downloads_needed() -> bool:
    try:
        with open(TIMESTAMP_FILE, "r", encoding="utf-8") as f:
            last_run = datetime.fromisoformat(f.readline().strip())
    except Exception:
        return True

    return (datetime.now(timezone.utc) - last_run) >= MAX_AGE


def iter_domain_pairs(path: str) -> Iterator[Tuple[str, str]]:
    """
    Stream (domain, nameserver) pairs from a zone file.
    Only NS records are parsed.
    """
    with open_zone(path) as fh:
        for line in fh:
            if not line or line[0] == ";":
                continue

            parts = line.split()
            if len(parts) < 5:
                continue

            if parts[3].upper() != "NS":
                continue

            domain = parts[0].rstrip(".").lower()
            nameserver = parts[4].rstrip(".").lower()

            yield domain, nameserver


async def process_zones(done: asyncio.Event, files: List[str]):
    await done.wait()

    for path in files:
        print(f"\nProcessing: {path}")

        count = 0
        sample = []

        for src, dst in iter_domain_pairs(path):
            if not is_our_nameserver(dst):
                continue

            count += 1

            if len(sample) < 10:
                sample.append((src, dst))

        print(f"  Parsed {count:,} domain pairs")
        for pair in sample:
            print(" ", pair)


async def main():
    if not USERNAME or not PASSWORD:
        raise RuntimeError("CZDS credentials must be set via environment variables")

    os.makedirs(ZONES_DIR, exist_ok=True)

    done_event = asyncio.Event()
    downloaded_files: List[str] = []

    processor = asyncio.create_task(process_zones(done_event, downloaded_files))

    if downloads_needed():
        async with CZDS(USERNAME, PASSWORD) as client:
            zone_links = await client.fetch_zone_links()

            targets = [
                url
                for url in zone_links
                if url.split("/")[-1].split(".")[0].lower() in TARGET_TLDS
            ]

            semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)

            async def download(url: str):
                path = await client.download_zone(url, ZONES_DIR, semaphore)
                downloaded_files.append(path)

            await asyncio.gather(*(download(url) for url in targets))

            with open(TIMESTAMP_FILE, "w", encoding="utf-8") as f:
                f.write(datetime.now(timezone.utc).isoformat() + "\n")
    else:
        for fname in os.listdir(ZONES_DIR):
            if fname.endswith(".gz"):
                downloaded_files.append(os.path.join(ZONES_DIR, fname))

    done_event.set()
    await processor

    print("\nDone.")


if __name__ == "__main__":
    asyncio.run(main())

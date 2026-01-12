#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import gzip
import os
import mysql.connector

from typing import (
    Iterator,
    Tuple,
    List,
    Set,
    Optional,
    TextIO,
)

from mysql.connector import MySQLConnection
from czds import CZDS

CZDS_USERNAME: Optional[str] = os.environ.get("CZDS_USERNAME")
CZDS_PASSWORD: Optional[str] = os.environ.get("CZDS_PASSWORD")

MYSQL_HOST: Optional[str] = os.environ.get("MYSQL_HOST")
MYSQL_USER: Optional[str] = os.environ.get("MYSQL_USER")
MYSQL_PASSWORD: Optional[str] = os.environ.get("MYSQL_PASSWORD")
MYSQL_DATABASE: Optional[str] = os.environ.get("MYSQL_DATABASE")

if not all(
    [
        CZDS_USERNAME,
        CZDS_PASSWORD,
        MYSQL_HOST,
        MYSQL_USER,
        MYSQL_PASSWORD,
        MYSQL_DATABASE,
    ]
):
    raise RuntimeError("Missing required environment variables")

MYSQL_CONFIG = {
    "host": MYSQL_HOST,
    "user": MYSQL_USER,
    "password": MYSQL_PASSWORD,
    "database": MYSQL_DATABASE,
}

TARGET_TLDS: Set[str] = {"com", "net", "org"}
ZONES_DIR: str = "zones"
MAX_CONCURRENT_DOWNLOADS: int = 3

OUR_NS_DOMAINS: Set[str] = {
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

def get_mysql_connection() -> MySQLConnection:
    return mysql.connector.connect(**MYSQL_CONFIG)


def truncate_nshosted(conn: MySQLConnection) -> None:
    with conn.cursor() as cursor:
        cursor.execute("TRUNCATE TABLE nshosted")
    conn.commit()

def insert_pairs(
    conn: MySQLConnection,
    pairs: List[Tuple[str, str]],
) -> None:
    if not pairs:
        return

    sql = """
        INSERT IGNORE INTO nshosted (domain, hostname)
        VALUES (%s, %s)
    """
    with conn.cursor() as cursor:
        cursor.executemany(sql, pairs)
    conn.commit()


def is_our_nameserver(nameserver: str) -> bool:
    if "europa" in nameserver:
        return False

    for suffix in OUR_NS_DOMAINS:
        if nameserver.endswith(suffix):
            return True
    return False

def open_zone(path: str) -> TextIO:
    if path.endswith(".gz"):
        return gzip.open(path, mode="rt", encoding="utf-8", errors="replace")
    return open(path, mode="r", encoding="utf-8", errors="replace")

def iter_domain_pairs(path: str) -> Iterator[Tuple[str, str]]:
    with open_zone(path) as file:
        for line in file:
            if not line or line[0] == ";":
                continue

            parts: List[str] = line.split()
            if len(parts) < 5:
                continue

            if parts[3].upper() != "NS":
                continue

            domain: str = parts[0].rstrip(".").lower()
            nameserver: str = parts[4].rstrip(".").lower()

            yield domain, nameserver

async def process_zones(
    ready_event: asyncio.Event,
    files: List[str],
) -> None:
    await ready_event.wait()

    conn: MySQLConnection = get_mysql_connection()
    try:
        print("Clearing nshosted table")
        truncate_nshosted(conn)

        for path in files:
            print(f"\nProcessing: {path}")

            batch: List[Tuple[str, str]] = []

            for domain, nameserver in iter_domain_pairs(path):
                if not is_our_nameserver(nameserver):
                    continue

                batch.append((domain, nameserver))

                if len(batch) >= 10_000:
                    insert_pairs(conn, batch)
                    batch.clear()

            if batch:
                insert_pairs(conn, batch)

            try:
                os.remove(path)
                print(f"Deleted: {path}")
            except OSError as exc:
                print(f"Failed to delete {path}: {exc}")

    finally:
        conn.close()

async def main() -> None:
    os.makedirs(ZONES_DIR, exist_ok=True)

    ready_event: asyncio.Event = asyncio.Event()
    downloaded_files: List[str] = []

    processor_task: asyncio.Task[None] = asyncio.create_task(
        process_zones(ready_event, downloaded_files)
    )

    async with CZDS(CZDS_USERNAME, CZDS_PASSWORD) as client:
        zone_links: List[str] = await client.fetch_zone_links()

        targets: List[str] = [
            url
            for url in zone_links
            if url.split("/")[-1].split(".")[0].lower() in TARGET_TLDS
        ]

        semaphore: asyncio.Semaphore = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)

        async def download(url: str) -> None:
            path: str = await client.download_zone(
                url,
                ZONES_DIR,
                semaphore,
            )
            downloaded_files.append(path)

        await asyncio.gather(*(download(url) for url in targets))

    ready_event.set()
    await processor_task


if __name__ == "__main__":
    asyncio.run(main())

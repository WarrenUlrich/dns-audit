#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import gzip
import os
import requests
import urllib3
import xml.etree.ElementTree as ET
import mysql.connector
import json

from dataclasses import dataclass
from typing import (
    Iterator,
    Tuple,
    List,
    Set,
    Optional,
    TextIO,
    Dict,
)

from mysql.connector import MySQLConnection
from czds import CZDS


@dataclass(frozen=True)
class CZDSConfig:
    username: str
    password: str


@dataclass(frozen=True)
class MySQLConfig:
    host: str
    user: str
    password: str
    database: str


@dataclass(frozen=True)
class PlatConfig:
    url: str
    username: str
    password: str


@dataclass(frozen=True)
class AppConfig:
    czds: CZDSConfig
    mysql: MySQLConfig
    plat: PlatConfig


def load_config(path: str = "/etc/dns-audit/config.json") -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)

    return AppConfig(
        czds=CZDSConfig(**raw["czds"]),
        mysql=MySQLConfig(**raw["mysql"]),
        plat=PlatConfig(**raw["plat"]),
    )


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

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def fetch_domain_customer_map(plat: PlatConfig) -> Dict[str, str]:
    xml_payload = f"""<?xml version="1.0"?>
    <PLATXML>
        <header></header>
        <body>
            <data_block>
                <protocol>Plat</protocol>
                <object>addusr</object>
                <action>SQL</action>
                <username>{plat.username}</username>
                <password>{plat.password}</password>
                <logintype>staff</logintype>
                <parameters>
                    <query>
                        SELECT domain, d_custid
                        FROM domain_dns
                        WHERE (d_active='Y' OR d_active='H')
                    </query>
                </parameters>
            </data_block>
        </body>
    </PLATXML>
    """

    response = requests.post(
        plat.url,
        data=xml_payload,
        headers={"Content-Type": "application/xml"},
        verify=False,
        timeout=30,
    )
    response.raise_for_status()

    root = ET.fromstring(response.text)
    attributes = root.find("./body/data_block/attributes")

    domain_map: Dict[str, str] = {}

    if attributes is not None:
        for block in attributes.findall("data_block"):
            record = {child.tag: child.text for child in block}
            domain = record.get("domain")
            custid = record.get("d_custid")
            if domain and custid:
                domain_map[domain.lower()] = custid

    return domain_map


def get_mysql_connection(mysql_cfg: MySQLConfig) -> MySQLConnection:
    return mysql.connector.connect(
        host=mysql_cfg.host,
        user=mysql_cfg.user,
        password=mysql_cfg.password,
        database=mysql_cfg.database,
    )


def truncate_nshosted(conn: MySQLConnection) -> None:
    with conn.cursor() as cursor:
        cursor.execute("TRUNCATE TABLE nshosted")
    conn.commit()


def insert_pairs(
    conn: MySQLConnection,
    pairs: List[Tuple[str, str, Optional[str]]],
) -> None:
    if not pairs:
        return

    sql = """
        INSERT IGNORE INTO nshosted (domain, hostname, customer_id)
        VALUES (%s, %s, %s)
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
            if not line or line.startswith(";"):
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
    domain_customer_map: Dict[str, str],
    mysql_cfg: MySQLConfig,
) -> None:
    await ready_event.wait()

    conn: MySQLConnection = get_mysql_connection(mysql_cfg)
    try:
        print("Clearing nshosted table")
        truncate_nshosted(conn)

        for path in files:
            print(f"\nProcessing: {path}")

            batch: List[Tuple[str, str, Optional[str]]] = []

            for domain, nameserver in iter_domain_pairs(path):
                if not is_our_nameserver(nameserver):
                    continue

                customer_id = domain_customer_map.get(domain)
                batch.append((domain, nameserver, customer_id))

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
    config: AppConfig = load_config()

    os.makedirs(ZONES_DIR, exist_ok=True)

    print("Loading domain → customer ID mapping")
    domain_customer_map = fetch_domain_customer_map(config.plat)
    print(f"Loaded {len(domain_customer_map)} domain mappings")

    ready_event: asyncio.Event = asyncio.Event()
    downloaded_files: List[str] = []

    processor_task: asyncio.Task[None] = asyncio.create_task(
        process_zones(
            ready_event,
            downloaded_files,
            domain_customer_map,
            config.mysql,
        )
    )

    async with CZDS(config.czds.username, config.czds.password) as client:
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

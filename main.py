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

from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, Tuple, Set, Iterator, List, Optional, TextIO
from mysql.connector import MySQLConnection
from czds import CZDS

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TARGET_TLDS = {"com", "net", "org"}
ZONES_DIR = "zones"
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


def load_config(path="/etc/dns-audit/config.json") -> AppConfig:
    with open(path, "r", encoding="utf-8") as f:
        raw = json.load(f)
    return AppConfig(
        czds=CZDSConfig(**raw["czds"]),
        mysql=MySQLConfig(**raw["mysql"]),
        plat=PlatConfig(**raw["plat"]),
    )


def mysql_conn(cfg: MySQLConfig) -> MySQLConnection:
    return mysql.connector.connect(
        host=cfg.host,
        user=cfg.user,
        password=cfg.password,
        database=cfg.database,
    )


def is_our_nameserver(ns: str) -> bool:
    labels = ns.lower().rstrip(".").split(".")
    for suffix in OUR_NS_DOMAINS:
        s = suffix.split(".")
        if labels[-len(s) :] == s:
            return True
    return False


def open_zone(path: str) -> TextIO:
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8", errors="replace")
    return open(path, "r", encoding="utf-8", errors="replace")


def iter_ns_records(path: str) -> Iterator[Tuple[str, str]]:
    with open_zone(path) as f:
        for line in f:
            if not line or line.startswith(";"):
                continue
            p = line.split()
            if len(p) >= 5 and p[3].upper() == "NS":
                yield p[0].rstrip(".").lower(), p[4].rstrip(".").lower()


def fetch_domain_customer_map(plat: PlatConfig) -> Dict[str, Tuple[int, str]]:
    xml = f"""<?xml version="1.0"?>
    <PLATXML><body><data_block>
        <protocol>Plat</protocol>
        <object>addusr</object>
        <action>SQL</action>
        <username>{plat.username}</username>
        <password>{plat.password}</password>
        <logintype>staff</logintype>
        <parameters><query>
            SELECT d.domain, c.id, c.email
            FROM domain_dns d
            JOIN customer c ON c.id = d.d_custid
        </query></parameters>
    </data_block></body></PLATXML>
    """

    r = requests.post(
        plat.url,
        data=xml,
        headers={"Content-Type": "application/xml"},
        verify=False,
        timeout=30,
    )
    r.raise_for_status()

    root = ET.fromstring(r.text)
    out: Dict[str, Tuple[int, str]] = {}

    for block in root.findall(".//attributes/data_block"):
        row = {c.tag: c.text for c in block}
        if row.get("domain") and row.get("id"):
            out[row["domain"].lower()] = (int(row["id"]), row.get("email"))

    return out


def rebuild_table(conn: MySQLConnection) -> None:
    ddl = """
    DROP TABLE IF EXISTS nshosted;
    CREATE TABLE nshosted (
        id               BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
        domain           VARCHAR(255) NOT NULL,
        hostname         VARCHAR(255) NULL,
        customer_id      INT UNSIGNED NULL,
        customer_email   VARCHAR(255) NULL,
        exception        ENUM('NXDOMAIN','NOT OUR SERVERS') NULL,

        PRIMARY KEY (id),
        UNIQUE KEY uniq_domain_host (domain, hostname),
        KEY idx_exception (exception),
        KEY idx_customer (customer_id)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
    """
    with conn.cursor() as c:
        for stmt in ddl.split(";"):
            if stmt.strip():
                c.execute(stmt)
    conn.commit()


def insert_rows(conn: MySQLConnection, rows: List[Tuple]) -> None:
    if not rows:
        return
    sql = """
    INSERT IGNORE INTO nshosted
    (domain, hostname, customer_id, customer_email, exception)
    VALUES (%s, %s, %s, %s, %s)
    """
    with conn.cursor() as c:
        c.executemany(sql, rows)
    conn.commit()


async def process_zones(
    ready: asyncio.Event,
    zone_files: List[str],
    domain_map: Dict[str, Tuple[int, str]],
    mysql_cfg: MySQLConfig,
) -> None:
    await ready.wait()

    conn = mysql_conn(mysql_cfg)
    rebuild_table(conn)

    domain_ns: Dict[str, Set[str]] = defaultdict(set)

    for path in zone_files:
        for d, ns in iter_ns_records(path):
            domain_ns[d].add(ns)
        os.remove(path)

    batch: List[Tuple] = []

    for domain, (cid, email) in domain_map.items():
        ns_set = domain_ns.get(domain)

        if not ns_set:
            batch.append((domain, None, cid, email, "NXDOMAIN"))
            continue

        if not any(is_our_nameserver(ns) for ns in ns_set):
            for ns in ns_set:
                batch.append((domain, ns, cid, email, "NOT OUR SERVERS"))
            continue

        for ns in ns_set:
            if is_our_nameserver(ns):
                batch.append((domain, ns, cid, email, None))

        if len(batch) >= 10_000:
            insert_rows(conn, batch)
            batch.clear()

    insert_rows(conn, batch)
    conn.close()


async def main() -> None:
    cfg = load_config()
    os.makedirs(ZONES_DIR, exist_ok=True)

    domain_map = fetch_domain_customer_map(cfg.plat)

    ready = asyncio.Event()
    zone_files: List[str] = []

    processor = asyncio.create_task(
        process_zones(ready, zone_files, domain_map, cfg.mysql)
    )

    async with CZDS(cfg.czds.username, cfg.czds.password) as czds:
        links = await czds.fetch_zone_links()
        targets = [
            u for u in links if u.split("/")[-1].split(".")[0].lower() in TARGET_TLDS
        ]

        sem = asyncio.Semaphore(MAX_CONCURRENT_DOWNLOADS)

        async def dl(url: str) -> None:
            p = await czds.download_zone(url, ZONES_DIR, sem)
            zone_files.append(p)

        await asyncio.gather(*(dl(u) for u in targets))

    ready.set()
    await processor


if __name__ == "__main__":
    asyncio.run(main())

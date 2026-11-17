#!/usr/bin/env python3
"""Tiny asyncio load generator for Korgan (see docs/LOAD_TESTING.md).

Requires: python3 and `pip install aiohttp`.

usage: load.py <base_url> <phase> [args...]
  register <count>                      register users loadN@example.com
  login <count> <seconds> <concurrency> POST /auth/login round-robin over users
  get <path> <seconds> <concurrency>    GET a path
Prints one JSON line with rps and latency percentiles (ms).
"""
import asyncio
import json
import sys
import time

import aiohttp


def pw(n: int) -> str:
    return f"L0ad-Test-Passw0rd-{n}!"


def pct(sorted_ms, p):
    if not sorted_ms:
        return None
    return round(sorted_ms[min(len(sorted_ms) - 1, int(len(sorted_ms) * p))], 2)


def summary(name, lat, codes, elapsed):
    lat = sorted(lat)
    return {
        "phase": name,
        "requests": len(lat),
        "seconds": round(elapsed, 2),
        "rps": round(len(lat) / elapsed, 1) if elapsed else 0,
        "p50_ms": pct(lat, 0.50),
        "p95_ms": pct(lat, 0.95),
        "p99_ms": pct(lat, 0.99),
        "max_ms": round(lat[-1], 2) if lat else None,
        "status": codes,
    }


async def run_for(seconds, concurrency, make_request, session):
    lat, codes = [], {}
    stop = time.monotonic() + seconds

    async def worker(wid):
        i = wid
        while time.monotonic() < stop:
            t0 = time.perf_counter()
            try:
                status = await make_request(session, i)
            except Exception as exc:  # noqa: BLE001
                status = type(exc).__name__
            lat.append((time.perf_counter() - t0) * 1000)
            codes[str(status)] = codes.get(str(status), 0) + 1
            i += concurrency

    t0 = time.monotonic()
    await asyncio.gather(*(worker(w) for w in range(concurrency)))
    return lat, codes, time.monotonic() - t0


async def main():
    base, phase = sys.argv[1], sys.argv[2]
    conn = aiohttp.TCPConnector(limit=0)
    timeout = aiohttp.ClientTimeout(total=60)
    async with aiohttp.ClientSession(connector=conn, timeout=timeout) as session:
        if phase == "register":
            count = int(sys.argv[3])
            sem = asyncio.Semaphore(16)
            codes = {}

            async def reg(n):
                async with sem:
                    async with session.post(
                        f"{base}/api/v1/auth/register",
                        json={"email": f"load{n}@example.com", "password": pw(n), "username": f"load{n}"},
                    ) as r:
                        codes[str(r.status)] = codes.get(str(r.status), 0) + 1

            await asyncio.gather(*(reg(n) for n in range(count)))
            print(json.dumps({"phase": "register", "status": codes}))
        elif phase == "login":
            count, seconds, conc = int(sys.argv[3]), float(sys.argv[4]), int(sys.argv[5])

            async def login(s, i):
                n = i % count
                async with s.post(
                    f"{base}/api/v1/auth/login",
                    headers={"X-Client-Type": "api"},
                    json={"email": f"load{n}@example.com", "password": pw(n)},
                ) as r:
                    await r.read()
                    return r.status

            lat, codes, el = await run_for(seconds, conc, login, session)
            print(json.dumps(summary("login", lat, codes, el)))
        elif phase == "get":
            path, seconds, conc = sys.argv[3], float(sys.argv[4]), int(sys.argv[5])

            async def get(s, i):
                async with s.get(f"{base}{path}") as r:
                    await r.read()
                    return r.status

            lat, codes, el = await run_for(seconds, conc, get, session)
            print(json.dumps(summary(f"GET {path}", lat, codes, el)))


asyncio.run(main())

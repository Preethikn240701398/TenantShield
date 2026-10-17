import asyncio
import ctypes
import os
import platform
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import redis.asyncio as aioredis
from app.core.config import settings
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy import text


def get_ram_gb() -> float:
    class MEMORYSTATUSEX(ctypes.Structure):
        _fields_ = [
            ("dwLength", ctypes.c_ulong),
            ("dwMemoryLoad", ctypes.c_ulong),
            ("ullTotalPhys", ctypes.c_ulonglong),
            ("ullAvailPhys", ctypes.c_ulonglong),
            ("ullTotalPageFile", ctypes.c_ulonglong),
            ("ullAvailPageFile", ctypes.c_ulonglong),
            ("ullTotalVirtual", ctypes.c_ulonglong),
            ("ullAvailVirtual", ctypes.c_ulonglong),
            ("sullAvailExtendedVirtual", ctypes.c_ulonglong),
        ]

    stat = MEMORYSTATUSEX()
    stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
    ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat))
    return round(stat.ullTotalPhys / (1024**3), 2)


def get_cpu_info() -> dict:
    cpu_name = platform.processor()
    try:
        import winreg
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"HARDWARE\DESCRIPTION\System\CentralProcessor\0",
        )
        val, _ = winreg.QueryValueEx(key, "ProcessorNameString")
        cpu_name = str(val).strip()
    except Exception:
        pass
    cores_logical = os.cpu_count() or 1
    return {
        "model": cpu_name,
        "logical_cores": cores_logical,
    }


async def get_services_info():
    pg_version = "Unknown"
    memurai_version = "Unknown"

    # PostgreSQL version
    try:
        engine = create_async_engine(settings.DATABASE_URL)
        async with engine.connect() as conn:
            res = await conn.execute(text("SELECT version();"))
            row = res.scalar()
            if row:
                pg_version = row
        await engine.dispose()
    except Exception as e:
        pg_version = f"Error: {e}"

    # Memurai / Redis version
    try:
        r = aioredis.from_url(settings.REDIS_URL)
        info = await r.info("server")
        memurai_version = info.get("redis_version", "Unknown")
        if "memurai_version" in info:
            memurai_version = f"Memurai {info['memurai_version']} (Redis {memurai_version})"
        await r.aclose()
    except Exception as e:
        memurai_version = f"Error: {e}"

    return {
        "postgres_version": pg_version,
        "memurai_version": memurai_version,
    }


async def main():
    cpu = get_cpu_info()
    ram = get_ram_gb()
    services = await get_services_info()
    print("=== ENVIRONMENT INFO ===")
    print(f"CPU Model: {cpu['model']}")
    print(f"Core Count: {cpu['logical_cores']}")
    print(f"RAM: {ram} GB")
    print(f"Windows Version: {platform.system()} {platform.release()} (Build {platform.version()})")
    print(f"Python: {sys.version.split()[0]}")
    print(f"PostgreSQL: {services['postgres_version']}")
    print(f"Memurai/Redis: {services['memurai_version']}")


if __name__ == "__main__":
    asyncio.run(main())

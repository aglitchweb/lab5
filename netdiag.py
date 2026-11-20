"""ЛР5. Автоматическая пошаговая диагностика сети."""

import csv
import datetime
import platform
import re
import socket
import subprocess
import time
from pathlib import Path


SYSTEM = platform.system()
IS_WINDOWS = SYSTEM == "Windows"
LOG_FILE = "diag_log.csv"


def run(cmd, timeout=15):
    """Запускает системную команду и возвращает код завершения и вывод."""
    try:
        encoding = "cp866" if IS_WINDOWS else "utf-8"
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
            encoding=encoding, errors="replace"
        )
        return result.returncode, result.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return -1, ""


def ping(host, count=3):
    """Возвращает (успех, среднее время ответа в миллисекундах)."""
    flag = "-n" if IS_WINDOWS else "-c"
    _, output = run(["ping", flag, str(count), str(host)])

    # Поддерживаются time=12.3 ms, время=12мс и time<1ms.
    matches = re.findall(
        r"(?:time|время)\s*[=<]\s*([0-9]+(?:[.,][0-9]+)?)\s*(?:ms|мс)?",
        output,
        flags=re.IGNORECASE
    )

    times = [float(value.replace(",", ".")) for value in matches]
    if not times:
        return False, None

    return True, round(sum(times) / len(times), 1)


def get_default_gateway():
    """Определяет шлюз по умолчанию для Windows, Linux или macOS."""
    if SYSTEM == "Linux":
        _, output = run(["ip", "route"])
        match = re.search(r"default via (\d+\.\d+\.\d+\.\d+)", output)
        return match.group(1) if match else None

    if IS_WINDOWS:
        _, output = run(["route", "print", "-4", "0.0.0.0"])
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", parts[2]):
                    return parts[2]
        return None

    if SYSTEM == "Darwin":
        _, output = run(["route", "-n", "get", "default"])
        match = re.search(r"gateway:\s*(\d+\.\d+\.\d+\.\d+)", output)
        return match.group(1) if match else None

    return None


def resolve(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None


def tcp_check(host, port, timeout=3):
    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, round((time.perf_counter() - start) * 1000, 1)
    except OSError:
        return False, None


def get_local_ip():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        sock.close()


ADVICE = {
    "Собственный интерфейс": [
        "Windows: проверьте адаптер командой ipconfig /all.",
        "Windows: проверьте состояние интерфейса командой netsh interface show interface.",
        "Linux: проверьте адреса командой ip addr.",
    ],
    "Шлюз по умолчанию": [
        "Windows: проверьте шлюз командой ipconfig /all и таблицу route print.",
        "Linux: проверьте маршрут командой ip route.",
        "Проверьте подключение к Wi-Fi или сетевой кабель.",
    ],
    "Внешняя сеть по IP (8.8.8.8)": [
        "Проверьте маршрут командой tracert 8.8.8.8 (Windows) или traceroute 8.8.8.8 (Linux).",
        "Проверьте наличие доступа в Интернет и правила брандмауэра.",
    ],
    "DNS (google.com)": [
        "Windows: проверьте DNS командой nslookup google.com.",
        "Windows: очистите DNS-кэш командой ipconfig /flushdns.",
        "Linux: проверьте DNS через resolvectl status или cat /etc/resolv.conf.",
    ],
    "Веб-сервис (google.com:443)": [
        "Проверьте DNS: nslookup google.com.",
        "Проверьте доступность HTTPS: curl -I https://google.com.",
        "Проверьте настройки прокси и брандмауэра.",
    ],
}


def log_result(step, ok, ms):
    """Добавляет строку в CSV-журнал диагностики."""
    file_exists = Path(LOG_FILE).exists()
    fields = ["datetime", "hostname", "local_ip", "step", "status", "ms"]

    with open(LOG_FILE, "a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fields)
        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "datetime": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "hostname": socket.gethostname(),
            "local_ip": get_local_ip(),
            "step": step,
            "status": "OK" if ok else "FAIL",
            "ms": "" if ms is None else ms,
        })


def main(gateway_override=None):
    gateway = gateway_override or get_default_gateway()
    if gateway is None:
        gateway = input("Шлюз не определён. Введите IP шлюза: ").strip()

    local_ip = get_local_ip()
    print(f"Локальный IP: {local_ip}   Шлюз: {gateway}\n")

    steps = [
        ("Стек TCP/IP (127.0.0.1)", lambda: ping("127.0.0.1")),
        ("Собственный интерфейс", lambda: ping(local_ip)),
        ("Шлюз по умолчанию", lambda: ping(gateway)),
        ("Внешняя сеть по IP (8.8.8.8)", lambda: ping("8.8.8.8")),
        ("DNS (google.com)", lambda: (resolve("google.com") is not None, None)),
        ("Веб-сервис (google.com:443)", lambda: tcp_check("google.com", 443)),
    ]

    for name, check in steps:
        ok, ms = check()
        log_result(name, ok, ms)
        extra = "" if ms is None else f"{ms} мс"
        print(f"[{'OK' if ok else 'FAIL'}] {name:32} {extra}")

        if not ok:
            print(f"\nДиагностика остановлена. Проблема на уровне: {name}")
            for recommendation in ADVICE.get(name, []):
                print("  -", recommendation)
            return 1

    print("\nВсе уровни работают.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

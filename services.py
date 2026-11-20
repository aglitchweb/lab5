"""ЛР5. Параллельная проверка доступности сетевых сервисов."""

import socket
import time
from concurrent.futures import ThreadPoolExecutor


VARIANT_PORT = 8060

SERVICES = [
    ("Google HTTPS", "google.com", 443),
    ("GitHub SSH", "github.com", 22),
    ("Google DNS TCP", "8.8.8.8", 53),
    ("Cloudflare DNS TCP", "1.1.1.1", 53),
    ("Локальный веб-сервер", "127.0.0.1", VARIANT_PORT),
    ("Закрытый локальный порт", "127.0.0.1", VARIANT_PORT + 1),
    ("Несуществующий домен", "no-such-host.example", 80),
    ("Фильтруемый адрес", "10.255.255.1", 80),
    ("Python HTTPS", "www.python.org", 443),
    ("GitHub HTTPS", "github.com", 443),
    ("Gmail IMAP", "imap.gmail.com", 993),
    ("Cloudflare HTTPS", "cloudflare.com", 443),
]


def check_service(name, host, port, timeout=3):
    """Проверяет DNS и TCP-порт; возвращает словарь с результатом."""
    result = {
        "name": name,
        "host": host,
        "port": port,
        "status": "?",
        "ms": None,
        "addresses": [],
    }

    try:
        info = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
        result["addresses"] = sorted({item[4][0] for item in info})
    except socket.gaierror:
        result["status"] = "DNS-ERROR"
        return result

    start = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result["status"] = "OPEN"
            result["ms"] = round((time.perf_counter() - start) * 1000, 1)
    except ConnectionRefusedError:
        result["status"] = "REFUSED"
        result["ms"] = round((time.perf_counter() - start) * 1000, 1)
    except (socket.timeout, TimeoutError):
        result["status"] = "TIMEOUT"
        result["ms"] = round((time.perf_counter() - start) * 1000, 1)
    except OSError:
        result["status"] = "ERROR"
        result["ms"] = round((time.perf_counter() - start) * 1000, 1)

    return result


def check_all_sequential(services, timeout=3):
    return [check_service(*service, timeout=timeout) for service in services]


def check_all_parallel(services, workers=10, timeout=3):
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(
            lambda service: check_service(*service, timeout=timeout),
            services
        ))
    return results


def print_table(results):
    print(f"{'Сервис':26}{'Узел':25}{'Порт':>6}  {'Статус':10}{'мс':>8}  Адресов")
    for result in results:
        ms = "" if result["ms"] is None else result["ms"]
        print(
            f"{result['name']:26}{result['host']:25}{result['port']:>6}  "
            f"{result['status']:10}{ms:>8}  {len(result['addresses'])}"
        )


if __name__ == "__main__":
    start = time.perf_counter()
    sequential = check_all_sequential(SERVICES)
    sequential_time = time.perf_counter() - start
    print("Последовательная проверка:")
    print_table(sequential)
    print(f"\nПоследовательно: {sequential_time:.2f} с")

    print("\nСравнение параллельной проверки:")
    for workers in (1, 2, 5, 10, 20):
        start = time.perf_counter()
        results = check_all_parallel(SERVICES, workers=workers)
        elapsed = time.perf_counter() - start
        print(f"workers = {workers:2}: {elapsed:.2f} с")

"""ЛР5. Аудит IP-адресов устройств по плану адресации."""

import csv
import ipaddress
import sys


def load_plan(path):
    """Читает plan.csv и возвращает {отдел: IPv4Network}."""
    with open(path, encoding="utf-8-sig", newline="") as file:
        return {
            row["department"]: ipaddress.ip_network(row["subnet"])
            for row in csv.DictReader(file)
        }


def load_devices(path):
    """Читает devices.csv: hostname,department,ip,gateway."""
    with open(path, encoding="utf-8-sig", newline="") as file:
        return list(csv.DictReader(file))


def audit(plan, devices):
    """Возвращает список кортежей (hostname, код, описание)."""
    problems = []
    seen_ips = {}

    for device in devices:
        host = device.get("hostname", "").strip()
        department = device.get("department", "").strip()

        try:
            ip = ipaddress.ip_address(device.get("ip", "").strip())
        except ValueError:
            problems.append((host, "E1", f"неверный формат IP: {device.get('ip', '')}"))
            continue

        if ip in seen_ips:
            problems.append((
                host, "E5",
                f"дубликат IP {ip}; этот адрес уже назначен устройству {seen_ips[ip]}"
            ))
        else:
            seen_ips[ip] = host

        network = plan.get(department)
        if network is None:
            problems.append((host, "E2", f"неизвестный отдел: {department}"))
            continue

        if ip not in network:
            problems.append((host, "E3", f"{ip} не входит в подсеть отдела {network}"))
        elif ip == network.network_address or ip == network.broadcast_address:
            problems.append((host, "E4", f"{ip} — адрес сети или broadcast подсети {network}"))

        try:
            gateway = ipaddress.ip_address(device.get("gateway", "").strip())
        except ValueError:
            problems.append((
                host, "E1",
                f"неверный формат шлюза: {device.get('gateway', '')}"
            ))
            continue

        if gateway == ip:
            problems.append((host, "E7", f"шлюз {gateway} совпадает с IP устройства"))
        elif gateway not in network:
            problems.append((
                host, "E6",
                f"шлюз {gateway} находится вне подсети отдела {network}"
            ))
        elif gateway != network.network_address + 1:
            problems.append((
                host, "W1",
                f"шлюз {gateway} не является первым адресом подсети "
                f"(ожидается {network.network_address + 1})"
            ))

    return problems


def save_report(problems, path="audit_report.csv"):
    """Сохраняет все найденные замечания в CSV."""
    with open(path, "w", newline="", encoding="utf-8-sig") as file:
        writer = csv.writer(file)
        writer.writerow(["hostname", "code", "severity", "description"])
        for host, code, description in problems:
            severity = "WARNING" if code.startswith("W") else "ERROR"
            writer.writerow([host, code, severity, description])


def print_summary(devices, problems):
    errors = sum(1 for _, code, _ in problems if not code.startswith("W"))
    warnings = sum(1 for _, code, _ in problems if code.startswith("W"))
    affected_hosts = {host for host, _, _ in problems}
    without_remarks = len(devices) - len(affected_hosts)

    print(f"\nПроверено устройств: {len(devices)}")
    print(f"Ошибок: {errors}")
    print(f"Предупреждений: {warnings}")
    print(f"Без замечаний: {without_remarks}")


def main():
    plan_file = sys.argv[1] if len(sys.argv) > 1 else "plan_v6.csv"
    devices_file = sys.argv[2] if len(sys.argv) > 2 else "devices.csv"
    report_file = "audit_report.csv"

    plan = load_plan(plan_file)
    devices = load_devices(devices_file)
    problems = audit(plan, devices)

    if problems:
        for host, code, description in problems:
            print(f"[{code}] {host:16} {description}")
    else:
        print("Замечаний не найдено.")

    print_summary(devices, problems)
    save_report(problems, report_file)
    print(f"Отчёт сохранён: {report_file}")

    return 1 if any(not code.startswith("W") for _, code, _ in problems) else 0


if __name__ == "__main__":
    raise SystemExit(main())

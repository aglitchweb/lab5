"""ЛР5. Единая утилита командной строки."""

import argparse
import time

import audit
import netcalc
import netdiag
import services


def cmd_calc(args):
    try:
        interface = netcalc.parse_cidr(args.address)
        for key, value in netcalc.subnet_info(str(interface)).items():
            print(f"{key:20}: {value}")
        return 0
    except ValueError as error:
        print("Ошибка:", error)
        return 1


def cmd_vlsm(args):
    try:
        departments = netcalc.parse_departments(",".join(args.departments))
        plan = netcalc.vlsm(args.base, departments, args.growth)
        errors = netcalc.check_plan(args.base, plan)
        if errors:
            for error in errors:
                print("[ОШИБКА]", error)
            return 1

        netcalc.print_plan(plan)
        print("\nИтоги:")
        for key, value in netcalc.plan_summary(args.base, plan).items():
            print(f"{key:20}: {value}")

        routes = netcalc.summarize(plan)
        print("Агрегированные маршруты:", ", ".join(map(str, routes["Агрегированные маршруты"])))
        print("Общая надсеть:", routes["Общая надсеть"])
        netcalc.save_plan_csv(plan, args.csv)
        print(f"План сохранён в {args.csv}")
        return 0

    except ValueError as error:
        print("Не удалось построить план:", error)
        try:
            suggested = netcalc.min_base_prefix(args.base, departments, args.growth)
            print(f"Минимальная подходящая сеть: {suggested}")
        except (ValueError, UnboundLocalError):
            pass
        return 1


def cmd_audit(args):
    try:
        plan = audit.load_plan(args.plan)
        devices = audit.load_devices(args.devices)
        problems = audit.audit(plan, devices)

        if problems:
            for host, code, description in problems:
                print(f"[{code}] {host:16} {description}")
        else:
            print("Замечаний не найдено.")

        audit.print_summary(devices, problems)
        audit.save_report(problems, args.report)
        print(f"Отчёт сохранён: {args.report}")
        return 1 if any(not code.startswith("W") for _, code, _ in problems) else 0
    except (OSError, KeyError, ValueError) as error:
        print("Ошибка аудита:", error)
        return 1


def cmd_diag(args):
    return netdiag.main(gateway_override=args.gateway)


def cmd_services(args):
    start = time.perf_counter()
    if args.parallel:
        results = services.check_all_parallel(
            services.SERVICES, workers=args.workers, timeout=args.timeout
        )
        mode = f"параллельно, workers={args.workers}"
    else:
        results = services.check_all_sequential(
            services.SERVICES, timeout=args.timeout
        )
        mode = "последовательно"

    elapsed = time.perf_counter() - start
    services.print_table(results)
    print(f"\nВремя ({mode}): {elapsed:.2f} с")
    failed = [item for item in results if item["status"] != "OPEN"]
    print(f"Недоступных/проблемных сервисов: {len(failed)}")
    return 1 if failed else 0


def build_parser():
    parser = argparse.ArgumentParser(description="Сетевые утилиты ЛР5")
    sub = parser.add_subparsers(dest="command", required=True)

    calc_parser = sub.add_parser("calc", help="калькулятор подсети")
    calc_parser.add_argument(
        "address",
        help="10.0.0.5/26 или '10.0.0.5 255.255.255.192'"
    )
    calc_parser.set_defaults(func=cmd_calc)

    vlsm_parser = sub.add_parser("vlsm", help="планирование VLSM")
    vlsm_parser.add_argument("base", help="базовая сеть, например 192.168.200.0/23")
    vlsm_parser.add_argument("departments", nargs="+", help="отделы в формате Имя=число")
    vlsm_parser.add_argument("--growth", type=int, default=0)
    vlsm_parser.add_argument("--csv", default="plan_v6.csv")
    vlsm_parser.set_defaults(func=cmd_vlsm)

    audit_parser = sub.add_parser("audit", help="аудит IP-адресов")
    audit_parser.add_argument("plan", help="CSV-план адресации")
    audit_parser.add_argument("devices", help="CSV-список устройств")
    audit_parser.add_argument("--report", default="audit_report.csv")
    audit_parser.set_defaults(func=cmd_audit)

    diag_parser = sub.add_parser("diag", help="диагностика подключения")
    diag_parser.add_argument("--gateway", default=None, help="задать шлюз вручную")
    diag_parser.set_defaults(func=cmd_diag)

    services_parser = sub.add_parser("services", help="проверка сетевых сервисов")
    services_parser.add_argument("--parallel", action="store_true")
    services_parser.add_argument("--workers", type=int, default=10)
    services_parser.add_argument("--timeout", type=float, default=3)
    services_parser.set_defaults(func=cmd_services)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())

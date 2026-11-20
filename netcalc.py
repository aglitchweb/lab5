"""ЛР5. Калькулятор подсетей и планировщик адресного пространства (VLSM)."""

import csv
import ipaddress


VARIANT = 6
VARIANT_BASE = "192.168.200.0/24"
VARIANT_DEPARTMENTS = {
    "Классы": 120,
    "Учителя": 35,
    "Администрация": 8,
}
VARIANT_GROWTH = 10


def subnet_info(cidr):
    """Возвращает основные сведения об IPv4-подсети."""
    iface = ipaddress.ip_interface(cidr)
    net = iface.network
    ip = iface.ip
    has_hosts = net.num_addresses > 2

    if ip.is_loopback:
        address_type = "loopback"
    elif ip.is_link_local:
        address_type = "link-local"
    elif ip.is_multicast:
        address_type = "multicast"
    elif ip.is_private:
        address_type = "частный"
    else:
        address_type = "публичный"

    binary_mask = ".".join(f"{part:08b}" for part in net.netmask.packed)

    return {
        "Адрес узла": str(iface.ip),
        "Адрес сети": str(net.network_address),
        "Маска": str(net.netmask),
        "Префикс": f"/{net.prefixlen}",
        "Broadcast": str(net.broadcast_address),
        "Первый узел": str(net.network_address + 1) if has_hosts else "-",
        "Последний узел": str(net.broadcast_address - 1) if has_hosts else "-",
        "Количество узлов": net.num_addresses - 2 if has_hosts else 0,
        "Wildcard": str(net.hostmask),
        "Маска (двоичная)": binary_mask,
        "Тип адреса": address_type,
    }


def parse_cidr(text):
    """Принимает IP/префикс или IP и маску через пробел."""
    text = text.strip()
    if not text:
        raise ValueError("пустой адрес")

    parts = text.split()
    if len(parts) == 1:
        if "/" not in parts[0]:
            raise ValueError("не указана маска")
        return ipaddress.ip_interface(parts[0])

    if len(parts) == 2:
        return ipaddress.ip_interface(f"{parts[0]}/{parts[1]}")

    raise ValueError("введите адрес с маской в одном из двух форматов")


def same_subnet(a, b):
    """Проверяет, находится ли адрес b в подсети адреса a."""
    iface = parse_cidr(a)
    ip = ipaddress.ip_address(b.strip())
    return ip in iface.network


def with_growth(need, growth):
    """Число устройств с запасом роста в процентах, округление вверх."""
    if need < 0 or growth < 0:
        raise ValueError("число устройств и запас роста не могут быть отрицательными")
    return (need * (100 + growth) + 99) // 100


def prefix_for(hosts):
    """Минимальный префикс IPv4-сети, в которой помещается hosts узлов."""
    if hosts < 0:
        raise ValueError("число узлов не может быть отрицательным")
    prefix = 32
    while prefix >= 0 and (2 ** (32 - prefix) - 2 < hosts):
        prefix -= 1
    if prefix < 0:
        raise ValueError("слишком большое количество узлов")
    return prefix


def vlsm(base_network, departments, growth=0):
    """Создаёт VLSM-план. Отделы размещаются от большего к меньшему."""
    base = ipaddress.ip_network(base_network, strict=False)
    if not isinstance(base, ipaddress.IPv4Network):
        raise ValueError("поддерживаются только IPv4-сети")

    plan = []
    current = base.network_address

    for name, need in sorted(departments.items(), key=lambda item: item[1], reverse=True):
        need_with_growth = with_growth(need, growth)
        prefix = prefix_for(need_with_growth)
        subnet = ipaddress.ip_network(f"{current}/{prefix}", strict=False)

        if subnet.network_address != current or not subnet.subnet_of(base):
            raise ValueError(f"Не хватает адресов для отдела «{name}»")

        plan.append({
            "name": name,
            "need": need,
            "need_g": need_with_growth,
            "subnet": subnet,
        })
        current = subnet.broadcast_address + 1

    return plan


def plan_summary(base_network, plan):
    """Возвращает сводку по выделенному адресному пространству."""
    base = ipaddress.ip_network(base_network, strict=False)
    allocated = sum(item["subnet"].num_addresses for item in plan)
    real_devices = sum(item["need"] for item in plan)
    free = base.num_addresses - allocated
    usage = round(real_devices / allocated * 100, 1) if allocated else 0.0

    return {
        "Всего адресов": base.num_addresses,
        "Выделено": allocated,
        "Свободно": free,
        "Использование, %": usage,
    }


def check_plan(base_network, plan):
    """Проверяет, что подсети находятся внутри базы и не пересекаются."""
    base = ipaddress.ip_network(base_network, strict=False)
    errors = []

    for item in plan:
        subnet = item["subnet"]
        if not subnet.subnet_of(base):
            errors.append(f"Подсеть отдела «{item['name']}» {subnet} выходит за пределы {base}")

    for i, first in enumerate(plan):
        for second in plan[i + 1:]:
            if first["subnet"].overlaps(second["subnet"]):
                errors.append(
                    f"Подсети отделов «{first['name']}» и «{second['name']}» пересекаются"
                )

    return errors


def min_base_prefix(base_network, departments, growth=0):
    """Находит наименьшую подходящую сеть, расширяя исходную сеть."""
    base = ipaddress.ip_network(base_network, strict=False)

    for prefix in range(base.prefixlen, -1, -1):
        candidate = ipaddress.ip_network(f"{base.network_address}/{prefix}", strict=False)
        try:
            vlsm(candidate, departments, growth)
            return candidate
        except ValueError:
            continue

    raise ValueError("Не удалось подобрать базовую сеть")


def summarize(plan):
    """Возвращает агрегированные маршруты и общую надсеть."""
    if not plan:
        return {"Агрегированные маршруты": [], "Общая надсеть": None}

    networks = [item["subnet"] for item in plan]
    collapsed = list(ipaddress.collapse_addresses(networks))

    common = networks[0]
    while not all(net.subnet_of(common) for net in networks):
        common = common.supernet()

    return {
        "Агрегированные маршруты": collapsed,
        "Общая надсеть": common,
    }


def save_plan_csv(plan, path):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow([
            "department", "need", "need_with_growth", "subnet", "gateway", "broadcast"
        ])
        for item in plan:
            net = item["subnet"]
            writer.writerow([
                item["name"],
                item["need"],
                item["need_g"],
                str(net),
                str(net.network_address + 1),
                str(net.broadcast_address),
            ])


def print_plan(plan):
    print(f"\n{'Отдел':20}{'Нужно':>8}{'С запасом':>11}  "
          f"{'Подсеть':20}{'Диапазон узлов':34}Broadcast")
    for item in plan:
        net = item["subnet"]
        host_range = f"{net.network_address + 1} - {net.broadcast_address - 1}"
        print(f"{item['name']:20}{item['need']:>8}{item['need_g']:>11}  "
              f"{str(net):20}{host_range:34}{net.broadcast_address}")


def parse_departments(text):
    """Преобразует строку вида 'Классы=120, Учителя=35' в словарь."""
    result = {}
    for part in text.split(","):
        if "=" not in part:
            raise ValueError(f"неверный формат отдела: {part}")
        name, count = part.split("=", 1)
        name = name.strip()
        count = int(count.strip())
        if not name or count < 0:
            raise ValueError("название отдела не должно быть пустым, число неотрицательное")
        result[name] = count
    return result


def menu():
    print("Сетевой калькулятор — вариант 6")
    while True:
        try:
            print("\n1 - Информация о подсети")
            print("2 - Находятся ли два узла в одной подсети")
            print("3 - План VLSM для варианта 6")
            print("0 - Выход")
            choice = input("Ваш выбор: ").strip()

            if choice == "0":
                print("Работа завершена")
                break

            if choice == "1":
                address = input("Введите IPv4-адрес и маску: ")
                for key, value in subnet_info(str(parse_cidr(address))).items():
                    print(f"{key:20}: {value}")

            elif choice == "2":
                first = input("Первый адрес с маской: ")
                second = input("Второй адрес без маски: ")
                print("Узлы в одной подсети:", "да" if same_subnet(first, second) else "нет")

            elif choice == "3":
                base = input(f"Базовая сеть [{VARIANT_BASE}]: ").strip() or VARIANT_BASE
                departments_text = input(
                    "Отделы (Название=число, через запятую) "
                    "[Классы=120, Учителя=35, Администрация=8]: "
                ).strip()
                if not departments_text:
                    departments = VARIANT_DEPARTMENTS
                else:
                    departments = parse_departments(departments_text)

                growth_text = input(f"Запас роста в процентах [{VARIANT_GROWTH}]: ").strip()
                growth = int(growth_text) if growth_text else VARIANT_GROWTH

                try:
                    plan = vlsm(base, departments, growth)
                    target_base = ipaddress.ip_network(base, strict=False)
                except ValueError as error:
                    suggested = min_base_prefix(base, departments, growth)
                    print(f"Не хватает адресов: {error}")
                    print(f"Предлагаемая базовая сеть: {suggested}")
                    answer = input("Построить план на предложенной сети? (д/н): ").strip().lower()
                    if answer not in ("д", "да", "y", "yes"):
                        continue
                    target_base = suggested
                    plan = vlsm(str(target_base), departments, growth)

                print_plan(plan)
                print("\nИтоги:")
                for key, value in plan_summary(target_base, plan).items():
                    print(f"{key:20}: {value}")
                print("Ошибки плана:", check_plan(target_base, plan) or "не обнаружены")
                route_info = summarize(plan)
                print("Агрегированные маршруты:", ", ".join(map(str, route_info["Агрегированные маршруты"])))
                print("Общая надсеть:", route_info["Общая надсеть"])
                save_plan_csv(plan, "plan_v6.csv")
                print("План сохранён в plan_v6.csv")

            else:
                print("Неизвестный пункт меню. Выберите 0, 1, 2 или 3.")

        except ValueError as error:
            print("Ошибка ввода:", error)
        except KeyboardInterrupt:
            print("\nРабота завершена")
            break


if __name__ == "__main__":
    menu()

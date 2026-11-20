"""Модульные тесты ЛР5. Запуск: python -m unittest -v."""

import ipaddress
import unittest

import audit
import netcalc


class TestSubnetInfo(unittest.TestCase):
    def test_slash24(self):
        info = netcalc.subnet_info("192.168.10.35/24")
        self.assertEqual(info["Адрес сети"], "192.168.10.0")
        self.assertEqual(info["Broadcast"], "192.168.10.255")
        self.assertEqual(info["Количество узлов"], 254)

    def test_slash30(self):
        info = netcalc.subnet_info("10.0.0.1/30")
        self.assertEqual(info["Количество узлов"], 2)
        self.assertEqual(info["Wildcard"], "0.0.0.3")

    def test_slash32(self):
        info = netcalc.subnet_info("8.8.8.8/32")
        self.assertEqual(info["Количество узлов"], 0)
        self.assertEqual(info["Первый узел"], "-")

    def test_link_local_type(self):
        info = netcalc.subnet_info("169.254.1.5/16")
        self.assertEqual(info["Тип адреса"], "link-local")

    def test_public_type(self):
        info = netcalc.subnet_info("8.8.8.8/32")
        self.assertEqual(info["Тип адреса"], "публичный")

    def test_loopback_type(self):
        info = netcalc.subnet_info("127.0.0.1/8")
        self.assertEqual(info["Тип адреса"], "loopback")


class TestParseCidr(unittest.TestCase):
    def test_two_formats_equal(self):
        first = netcalc.parse_cidr("10.0.0.5/26")
        second = netcalc.parse_cidr("10.0.0.5 255.255.255.192")
        self.assertEqual(first, second)

    def test_invalid_address(self):
        with self.assertRaises(ValueError):
            netcalc.parse_cidr("192.168.1.300/24")

    def test_missing_mask(self):
        with self.assertRaisesRegex(ValueError, "не указана маска"):
            netcalc.parse_cidr("10.0.0.5")

    def test_same_subnet(self):
        self.assertTrue(netcalc.same_subnet("10.0.0.5/24", "10.0.0.90"))
        self.assertFalse(netcalc.same_subnet("10.0.0.5/24", "10.0.1.10"))


class TestVlsm(unittest.TestCase):
    def test_growth(self):
        self.assertEqual(netcalc.with_growth(60, 10), 66)

    def test_not_enough_addresses(self):
        with self.assertRaises(ValueError):
            netcalc.vlsm("10.0.0.0/26", {"A": 50, "B": 30})

    def test_sorted_descending(self):
        plan = netcalc.vlsm(
            "192.168.200.0/23",
            {"Классы": 120, "Учителя": 35, "Администрация": 8},
            growth=10,
        )
        sizes = [item["subnet"].num_addresses for item in plan]
        self.assertEqual(sizes, sorted(sizes, reverse=True))

    def test_first_subnet_starts_at_base(self):
        plan = netcalc.vlsm(
            "192.168.200.0/23",
            {"Классы": 120, "Учителя": 35, "Администрация": 8},
            growth=10,
        )
        self.assertEqual(str(plan[0]["subnet"].network_address), "192.168.200.0")

    def test_plan_is_valid(self):
        plan = netcalc.vlsm(
            "192.168.200.0/23",
            {"Классы": 120, "Учителя": 35, "Администрация": 8},
            growth=10,
        )
        self.assertEqual(netcalc.check_plan("192.168.200.0/23", plan), [])

    def test_min_base_prefix(self):
        result = netcalc.min_base_prefix("10.0.0.0/26", {"A": 50, "B": 30})
        self.assertEqual(str(result), "10.0.0.0/25")

    def test_variant_needs_slash23(self):
        result = netcalc.min_base_prefix(
            "192.168.200.0/24",
            {"Классы": 120, "Учителя": 35, "Администрация": 8},
            growth=10,
        )
        self.assertEqual(str(result), "192.168.200.0/23")

    def test_summary(self):
        plan = netcalc.vlsm(
            "192.168.200.0/23",
            {"Классы": 120, "Учителя": 35, "Администрация": 8},
            growth=10,
        )
        summary = netcalc.plan_summary("192.168.200.0/23", plan)
        self.assertEqual(summary["Выделено"], 336)
        self.assertEqual(summary["Свободно"], 176)

    def test_aggregation(self):
        plan = netcalc.vlsm(
            "192.168.200.0/23",
            {"Классы": 120, "Учителя": 35, "Администрация": 8},
            growth=10,
        )
        routes = netcalc.summarize(plan)
        self.assertEqual(str(routes["Общая надсеть"]), "192.168.200.0/23")


class TestAudit(unittest.TestCase):
    def test_duplicate_and_broadcast_detected(self):
        plan = {"A": ipaddress.ip_network("10.0.0.0/24")}
        devices = [
            {"hostname": "pc-01", "department": "A", "ip": "10.0.0.10", "gateway": "10.0.0.1"},
            {"hostname": "pc-02", "department": "A", "ip": "10.0.0.10", "gateway": "10.0.0.1"},
            {"hostname": "pc-03", "department": "A", "ip": "10.0.0.255", "gateway": "10.0.0.1"},
        ]
        codes = {code for _, code, _ in audit.audit(plan, devices)}
        self.assertIn("E5", codes)
        self.assertIn("E4", codes)

    def test_gateway_outside_subnet(self):
        plan = {"A": ipaddress.ip_network("10.0.0.0/24")}
        devices = [
            {"hostname": "pc-01", "department": "A", "ip": "10.0.0.10", "gateway": "10.0.1.1"},
        ]
        codes = {code for _, code, _ in audit.audit(plan, devices)}
        self.assertIn("E6", codes)

    def test_gateway_equal_ip(self):
        plan = {"A": ipaddress.ip_network("10.0.0.0/24")}
        devices = [
            {"hostname": "pc-01", "department": "A", "ip": "10.0.0.10", "gateway": "10.0.0.10"},
        ]
        codes = {code for _, code, _ in audit.audit(plan, devices)}
        self.assertIn("E7", codes)


if __name__ == "__main__":
    unittest.main()

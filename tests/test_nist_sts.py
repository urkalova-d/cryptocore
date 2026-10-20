"""Проверка собственной реализации тестов NIST SP 800-22.

Две группы проверок:
1. Примеры из документа NIST SP 800-22 (маленькие последовательности с известными p-значениями).
2. Поведение на данных: случайные данные из CSPRNG должны проходить, плохие - проваливаться.
"""
import math
import unittest

import numpy as np

from src.csprng import generate_random_bytes
from tests import nist_sts as n

B = n.bits_from_string


class TestSpecialFunctions(unittest.TestCase):
    def test_igamc_exponential(self):
        for x in (0.1, 1.0, 2.0, 7.5):
            self.assertAlmostEqual(n.igamc(1, x), math.exp(-x), places=12)

    def test_igamc_erfc(self):
        for x in (0.3, 2.0, 9.0):
            self.assertAlmostEqual(n.igamc(0.5, x), math.erfc(math.sqrt(x)), places=12)

    def test_igamc_bounds(self):
        self.assertEqual(n.igamc(3, 0), 1.0)
        with self.assertRaises(ValueError):
            n.igamc(0, 1)


class TestNistExamples(unittest.TestCase):
    """Значения из примеров документа SP 800-22 rev. 1a (раздел 2)."""

    def test_frequency(self):
        self.assertAlmostEqual(n.frequency_test(B("1011010101")), 0.527089, places=5)

    def test_block_frequency(self):
        self.assertAlmostEqual(n.block_frequency_test(B("0110011010"), M=3), 0.801252, places=5)

    def test_runs(self):
        self.assertAlmostEqual(n.runs_test(B("1001101011")), 0.147232, places=5)

    def test_longest_run(self):
        e = ("11001100000101010110110001001100111000000000001001001101010100010001"
             "001111010110100000001101011111001100111001101101100010110010")
        self.assertAlmostEqual(n.longest_run_test(B(e)), 0.180609, places=3)

    def test_cumulative_sums(self):
        forward, _ = n.cumulative_sums_test(B("1011010111"))
        self.assertAlmostEqual(forward, 0.4116588, places=5)

    def test_serial(self):
        p1, p2 = n.serial_test(B("0011011101"), m=3)
        self.assertAlmostEqual(p1, 0.808792, places=5)
        self.assertAlmostEqual(p2, 0.670320, places=5)

    def test_approximate_entropy(self):
        self.assertAlmostEqual(n.approximate_entropy_test(B("0100110101"), m=3), 0.261961, places=5)

    def test_overlapping_probabilities(self):
        expected = [0.364091, 0.185659, 0.139381, 0.100571, 0.070432, 0.139865]
        for got, want in zip(n._OVERLAPPING_PI, expected):
            self.assertAlmostEqual(got, want, places=5)

    def test_linear_complexity_example(self):
        self.assertEqual(n.berlekamp_massey([int(c) for c in "1101011110001"]), 4)

    def test_gf2_rank(self):
        self.assertEqual(n.gf2_rank([0b110, 0b011, 0b101]), 2)   # третья строка = сумма первых двух
        self.assertEqual(n.gf2_rank([0b100, 0b010, 0b001]), 3)
        self.assertEqual(n.gf2_rank([0, 0, 0]), 0)

    def test_aperiodic_template_count(self):
        self.assertEqual(len(n.aperiodic_templates(9)), 148)


class TestOnData(unittest.TestCase):
    N = 1 << 20

    @classmethod
    def setUpClass(cls):
        cls.good = n.bits_from_bytes(generate_random_bytes(cls.N // 8))

    def test_good_stream_passes_fast_tests(self):
        b = self.good
        for name, p in [("freq", n.frequency_test(b)), ("block", n.block_frequency_test(b)),
                        ("runs", n.runs_test(b)), ("longest", n.longest_run_test(b)),
                        ("fft", n.dft_test(b)), ("apen", n.approximate_entropy_test(b)),
                        ("cusum", n.cumulative_sums_test(b)[0])]:
            # один поток может случайно дать p < 0.01 (1 %), поэтому порог ниже
            self.assertGreater(p, 0.0001, name)

    def test_zeros_fail(self):
        b = n.make_control("zeros", self.N)
        self.assertLess(n.frequency_test(b), 0.01)
        self.assertLess(n.cumulative_sums_test(b)[0], 0.01)
        self.assertLess(n.approximate_entropy_test(b), 0.01)

    def test_alternating_fail(self):
        b = n.make_control("alternating", self.N)
        self.assertLess(n.runs_test(b), 0.01)
        self.assertLess(n.serial_test(b)[0], 0.01)
        self.assertLess(n.dft_test(b), 0.01)

    def test_biased_fail(self):
        self.assertLess(n.frequency_test(n.make_control("biased", self.N)), 0.01)

    def test_analyze_uniform(self):
        res = n.analyze([i / 100 + 0.005 for i in range(100)])
        self.assertTrue(res["rate_ok"] and res["uniform_ok"])
        res = n.analyze([0.0] * 100)
        self.assertFalse(res["rate_ok"])


if __name__ == "__main__":
    unittest.main()

"""Собственная реализация 15 статистических тестов NIST SP 800-22 rev. 1a.

Это НЕ официальный пакет NIST STS, а независимая реализация тех же тестов
на Python по тексту документа SP 800-22. Корректность проверяется в
tests/test_nist_sts.py на примерах из самого документа NIST (там приведены
входные последовательности и ожидаемые p-значения).

Запуск из корня проекта:
    python -m tests.nist_sts --input random_test_data.bin
    python -m tests.nist_sts --input random_test_data.bin --output report.md --jobs 4
    python -m tests.nist_sts --control zeros --streams 3      # контрольный "плохой" генератор

Входной файл режется на независимые потоки по --stream-bits бит (по умолчанию
2**20, то есть чуть больше миллиона: степень двойки нужна для быстрого
преобразования Фурье, а длина подходит под рекомендации NIST для всех тестов).
Для каждого потока считаются p-значения всех тестов, затем делается
итоговый анализ из раздела 4.2 документа: доля потоков с p >= 0.01 и
равномерность распределения p-значений.

Требуется numpy (pip install -r requirements-dev.txt).
"""
import argparse
import math
import os
import platform
import re
import sys
import time
from concurrent.futures import ProcessPoolExecutor

import numpy as np

ALPHA = 0.01              # уровень значимости: тест пройден, если p >= ALPHA
STREAM_BITS = 1 << 20     # длина одного потока по умолчанию
MIN_CYCLES = 500          # минимум циклов для тестов случайных экскурсий

try:
    _popcount = int.bit_count          # Python 3.10+
except AttributeError:                 # запасной вариант для старых версий
    def _popcount(x):
        return bin(x).count("1")


# ----------------------------------------------------------------------
# Специальные функции
# ----------------------------------------------------------------------

def igamc(a, x):
    """Регуляризованная верхняя неполная гамма-функция Q(a, x).

    Через неё считаются p-значения всех тестов на основе хи-квадрат:
    p = igamc(число_степеней_свободы / 2, хи_квадрат / 2).
    Для x < a + 1 берётся ряд для P(a, x) и Q = 1 - P, иначе непрерывная
    дробь Лежандра, посчитанная методом Ленца (как в Numerical Recipes).
    """
    if a <= 0 or x < 0:
        raise ValueError("igamc: нужно a > 0 и x >= 0")
    if x == 0:
        return 1.0

    log_front = -x + a * math.log(x) - math.lgamma(a)

    if x < a + 1:
        term = 1.0 / a
        total = term
        n = a
        for _ in range(200000):
            n += 1
            term *= x / n
            total += term
            if term < total * 1e-17:
                break
        return max(0.0, 1.0 - total * math.exp(log_front))

    tiny = 1e-300
    b = x + 1.0 - a
    c = 1.0 / tiny
    d = 1.0 / b
    h = d
    for i in range(1, 200000):
        an = -i * (i - a)
        b += 2.0
        d = an * d + b
        if abs(d) < tiny:
            d = tiny
        c = b + an / c
        if abs(c) < tiny:
            c = tiny
        d = 1.0 / d
        delta = d * c
        h *= delta
        if abs(delta - 1.0) < 1e-16:
            break
    return min(1.0, math.exp(log_front) * h)


def _phi(x):
    """Функция распределения стандартного нормального закона."""
    return 0.5 * math.erfc(-x / math.sqrt(2.0))


# ----------------------------------------------------------------------
# Представление данных
# ----------------------------------------------------------------------

def bits_from_string(text):
    """'0110...' -> массив нулей и единиц (используется в примерах из NIST)."""
    return np.frombuffer(text.encode("ascii"), dtype=np.uint8) - 48


def bits_from_bytes(data):
    """Байты -> массив битов, старший бит каждого байта идёт первым."""
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _bit_string(bits):
    """Массив битов -> строка '0' и '1' (для быстрого поиска шаблонов)."""
    return (bits + 48).astype(np.uint8).tobytes().decode("ascii")


# ----------------------------------------------------------------------
# 1. Частотный (монобитный) тест
# ----------------------------------------------------------------------

def frequency_test(bits):
    """Доля единиц должна быть близка к 1/2."""
    n = len(bits)
    s = 2 * int(bits.sum()) - n
    return math.erfc(abs(s) / math.sqrt(n) / math.sqrt(2.0))


# ----------------------------------------------------------------------
# 2. Частотный тест внутри блока
# ----------------------------------------------------------------------

def block_frequency_test(bits, M=20000):
    """Доля единиц в каждом блоке из M бит должна быть близка к 1/2."""
    n = len(bits)
    N = n // M
    blocks = bits[:N * M].reshape(N, M)
    pi = blocks.sum(axis=1) / M
    chi2 = 4.0 * M * float(((pi - 0.5) ** 2).sum())
    return igamc(N / 2.0, chi2 / 2.0)


# ----------------------------------------------------------------------
# 3. Тест серий
# ----------------------------------------------------------------------

def runs_test(bits):
    """Общее число серий (подряд идущих одинаковых бит) как у случайной последовательности."""
    n = len(bits)
    pi = int(bits.sum()) / n
    # предварительное условие из документа: иначе частотный тест уже провален
    if abs(pi - 0.5) >= 2.0 / math.sqrt(n):
        return 0.0
    v_obs = 1 + int(np.count_nonzero(bits[1:] != bits[:-1]))
    return math.erfc(abs(v_obs - 2.0 * n * pi * (1 - pi))
                     / (2.0 * math.sqrt(2.0 * n) * pi * (1 - pi)))


# ----------------------------------------------------------------------
# 4. Тест на самую длинную серию единиц в блоке
# ----------------------------------------------------------------------

# для каждой длины блока M: число блоков N, границы классов lo..hi, вероятности классов
_LONGEST_RUN_PARAMS = {
    8: (16, 1, 4, [0.2148, 0.3672, 0.2305, 0.1875]),
    128: (49, 4, 9, [0.1174, 0.2430, 0.2493, 0.1752, 0.1027, 0.1124]),
    10000: (75, 10, 16, [0.0882, 0.2092, 0.2483, 0.1933, 0.1208, 0.0675, 0.0727]),
}


def _longest_run_of_ones(block):
    padded = np.concatenate(([0], block, [0])).astype(np.int8)
    d = np.diff(padded)
    starts = np.flatnonzero(d == 1)
    ends = np.flatnonzero(d == -1)
    return int((ends - starts).max()) if len(starts) else 0


def longest_run_test(bits):
    n = len(bits)
    if n < 128:
        raise ValueError("для теста самой длинной серии нужно не меньше 128 бит")
    M = 8 if n < 6272 else (128 if n < 750000 else 10000)
    N, lo, hi, pi = _LONGEST_RUN_PARAMS[M]

    counts = [0] * (hi - lo + 1)
    for i in range(N):
        longest = _longest_run_of_ones(bits[i * M:(i + 1) * M])
        # серии короче lo и длиннее hi сливаются в крайние классы
        counts[min(max(longest, lo) - lo, hi - lo)] += 1

    chi2 = sum((counts[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(len(counts)))
    return igamc((len(counts) - 1) / 2.0, chi2 / 2.0)


# ----------------------------------------------------------------------
# 5. Тест рангов бинарных матриц
# ----------------------------------------------------------------------

def gf2_rank(rows):
    """Ранг матрицы над GF(2); строки заданы целыми числами (по биту на столбец)."""
    rank = 0
    rows = list(rows)
    while rows:
        pivot = rows.pop()
        if pivot:
            rank += 1
            low = pivot & -pivot          # опорный столбец: младший единичный бит
            rows = [r ^ pivot if r & low else r for r in rows]
    return rank


def binary_matrix_rank_test(bits, M=32, Q=32):
    """Ранги матриц M x Q, заполненных битами потока, должны быть как у случайных матриц."""
    n = len(bits)
    N = n // (M * Q)
    s = _bit_string(bits)
    full = one_less = 0
    for k in range(N):
        base = k * M * Q
        rows = [int(s[base + i * Q: base + (i + 1) * Q], 2) for i in range(M)]
        rank = gf2_rank(rows)
        if rank == M:
            full += 1
        elif rank == M - 1:
            one_less += 1
    rest = N - full - one_less
    # вероятности рангов M, M-1 и меньше для больших матриц (из документа NIST)
    p_full, p_less, p_rest = 0.2888, 0.5776, 0.1336
    chi2 = ((full - p_full * N) ** 2 / (p_full * N)
            + (one_less - p_less * N) ** 2 / (p_less * N)
            + (rest - p_rest * N) ** 2 / (p_rest * N))
    return math.exp(-chi2 / 2.0)          # две степени свободы: igamc(1, x) = exp(-x)


# ----------------------------------------------------------------------
# 6. Спектральный тест (дискретное преобразование Фурье)
# ----------------------------------------------------------------------

def dft_test(bits, variance_divisor=3.8):
    """Число пиков спектра ниже порога должно быть около 95 %.

    В исходном документе дисперсия равна n*0.95*0.05/4, в актуальных версиях
    официального STS (2.1.2) используется поправка 3.8 (Kim, Umeno, Hasegawa,
    2004). По умолчанию берём поправленное значение; пример из документа
    проверяется с делителем 4.
    """
    n = len(bits)
    spectrum = np.abs(np.fft.fft(2.0 * bits - 1.0))[:n // 2]
    threshold = math.sqrt(math.log(1.0 / 0.05) * n)
    n0 = 0.95 * n / 2.0
    n1 = int(np.count_nonzero(spectrum < threshold))
    d = (n1 - n0) / math.sqrt(n * 0.95 * 0.05 / variance_divisor)
    return math.erfc(abs(d) / math.sqrt(2.0))


# ----------------------------------------------------------------------
# 7. Тест несовпадающих (непересекающихся) шаблонов
# ----------------------------------------------------------------------

def aperiodic_templates(m):
    """Все m-битные шаблоны без нетривиальных самоперекрытий (для m=9 их 148)."""
    result = []
    for v in range(1 << m):
        t = format(v, "0%db" % m)
        if all(t[k:] != t[:m - k] for k in range(1, m)):
            result.append(t)
    return result


def non_overlapping_template_test(bits, m=9, N=8, templates=None):
    """Число вхождений каждого шаблона в блоки; возвращает {шаблон: p-значение}."""
    n = len(bits)
    M = n // N
    s = _bit_string(bits)
    blocks = [s[i * M:(i + 1) * M] for i in range(N)]
    mu = (M - m + 1) / 2.0 ** m
    sigma2 = M * (1.0 / 2.0 ** m - (2 * m - 1) / 2.0 ** (2 * m))
    result = {}
    for t in (templates if templates is not None else aperiodic_templates(m)):
        # str.count считает непересекающиеся вхождения слева направо:
        # после совпадения поиск продолжается за его концом, как требует тест
        chi2 = sum((b.count(t) - mu) ** 2 for b in blocks) / sigma2
        result[t] = igamc(N / 2.0, chi2 / 2.0)
    return result


# ----------------------------------------------------------------------
# 8. Тест пересекающихся шаблонов
# ----------------------------------------------------------------------

def overlapping_template_probabilities(m=9, M=1032, K=5):
    """Точные вероятности встретить 0..K-1 и >=K пересекающихся вхождений 1^m в блоке M бит.

    Считаются динамическим программированием по длине текущей серии единиц.
    Совпадают с константами, исправленными в официальном STS
    (0.364091, 0.185659, 0.139381, 0.100571, 0.0704323, 0.139865).
    """
    state = np.zeros((m + 1, K + 1))      # [длина текущей серии (не больше m)][число вхождений]
    state[0, 0] = 1.0
    for _ in range(M):
        new = np.zeros_like(state)
        new[0, :] += 0.5 * state.sum(axis=0)        # выпал 0: серия обрывается
        for r in range(m + 1):                       # выпала 1: серия растёт
            nr = min(r + 1, m)
            for c in range(K + 1):
                nc = min(c + 1, K) if r + 1 >= m else c
                new[nr, nc] += 0.5 * state[r, c]
        state = new
    return state.sum(axis=0).tolist()


_OVERLAPPING_PI = overlapping_template_probabilities()


def overlapping_template_test(bits, m=9, M=1032, pi=None):
    n = len(bits)
    N = n // M
    pi = _OVERLAPPING_PI if pi is None else pi
    s = _bit_string(bits)
    rx = re.compile("(?=%s)" % ("1" * m))          # опережающая проверка даёт пересекающиеся вхождения
    nu = [0] * 6
    for i in range(N):
        count = len(rx.findall(s[i * M:(i + 1) * M]))
        nu[min(count, 5)] += 1
    chi2 = sum((nu[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(6))
    return igamc(5 / 2.0, chi2 / 2.0)


# ----------------------------------------------------------------------
# 9. Универсальный статистический тест Маурера
# ----------------------------------------------------------------------

# L: (математическое ожидание, дисперсия) из таблицы документа NIST
_UNIVERSAL_TABLE = {
    6: (5.2177052, 2.954), 7: (6.1962507, 3.125), 8: (7.1836656, 3.238),
    9: (8.1764248, 3.311), 10: (9.1723243, 3.356), 11: (10.170032, 3.384),
    12: (11.168765, 3.401), 13: (12.168070, 3.410), 14: (13.167693, 3.416),
    15: (14.167488, 3.419), 16: (15.167379, 3.421),
}
# минимальная длина последовательности для каждого L
_UNIVERSAL_MIN_N = [(387840, 6), (904960, 7), (2068480, 8), (4654080, 9), (10342400, 10),
                    (22753280, 11), (49643520, 12), (107560960, 13), (231669760, 14),
                    (496435200, 15), (1059061760, 16)]


def _universal_statistic(bits, L, Q):
    """Среднее значение log2 расстояний между одинаковыми L-битными блоками."""
    n = len(bits)
    nb = n // L
    weights = 1 << np.arange(L - 1, -1, -1, dtype=np.int64)
    blocks = (bits[:nb * L].reshape(nb, L).astype(np.int64) @ weights).tolist()
    K = nb - Q
    last_seen = {}
    for i in range(Q):                     # инициализирующая часть: только запоминаем позиции
        last_seen[blocks[i]] = i + 1
    total = 0.0
    for i in range(Q, nb):                 # тестовая часть
        b = blocks[i]
        total += math.log2(i + 1 - last_seen.get(b, 0))
        last_seen[b] = i + 1
    return total / K, K


def universal_test(bits):
    """Сжимаемость последовательности: у случайной данные почти не сжимаются."""
    n = len(bits)
    L = 0
    for min_n, l_value in _UNIVERSAL_MIN_N:
        if n >= min_n:
            L = l_value
    if L == 0:
        raise ValueError("для теста Маурера нужно не меньше 387840 бит")
    Q = 10 * 2 ** L
    fn, K = _universal_statistic(bits, L, Q)
    expected, variance = _UNIVERSAL_TABLE[L]
    c = 0.7 - 0.8 / L + (4 + 32.0 / L) * K ** (-3.0 / L) / 15.0
    sigma = c * math.sqrt(variance / K)
    return math.erfc(abs(fn - expected) / (math.sqrt(2.0) * sigma))


# ----------------------------------------------------------------------
# 10. Тест линейной сложности
# ----------------------------------------------------------------------

def berlekamp_massey(seq):
    """Линейная сложность двоичной последовательности (алгоритм Берлекэмпа-Мэсси).

    Многочлены связи хранятся целыми числами: бит i числа C - коэффициент
    при x^i. Невязка считается как чётность числа единиц в C & S, где в S
    бит j равен s[n-j], поэтому каждый шаг - несколько операций над
    длинными целыми, а не цикл по коэффициентам.
    """
    C = 1
    B = 1
    L = 0
    m = -1
    window = 0
    for n, bit in enumerate(seq):
        window = (window << 1) | bit
        if _popcount(C & window) & 1:      # невязка равна 1
            T = C
            C ^= B << (n - m)
            if 2 * L <= n:
                L = n + 1 - L
                m = n
                B = T
    return L


def linear_complexity_test(bits, M=500):
    n = len(bits)
    N = n // M
    mu = M / 2.0 + (9 + (-1) ** (M + 1)) / 36.0 - (M / 3.0 + 2.0 / 9.0) / 2.0 ** M
    pi = [0.010417, 0.03125, 0.125, 0.5, 0.25, 0.0625, 0.020833]
    nu = [0] * 7
    sign = (-1) ** M
    for i in range(N):
        L = berlekamp_massey(bits[i * M:(i + 1) * M].tolist())
        t = sign * (L - mu) + 2.0 / 9.0
        if t <= -2.5:
            nu[0] += 1
        elif t <= -1.5:
            nu[1] += 1
        elif t <= -0.5:
            nu[2] += 1
        elif t <= 0.5:
            nu[3] += 1
        elif t <= 1.5:
            nu[4] += 1
        elif t <= 2.5:
            nu[5] += 1
        else:
            nu[6] += 1
    chi2 = sum((nu[i] - N * pi[i]) ** 2 / (N * pi[i]) for i in range(7))
    return igamc(3.0, chi2 / 2.0)


# ----------------------------------------------------------------------
# 11. Серийный тест и 12. Тест приближённой энтропии
# ----------------------------------------------------------------------

def _window_counts(bits, m):
    """Сколько раз встречается каждый m-битный шаблон (последовательность считается циклической)."""
    n = len(bits)
    ext = np.concatenate((bits, bits[:m - 1])).astype(np.int64)
    value = np.zeros(n, dtype=np.int64)
    for j in range(m):
        value = (value << 1) | ext[j:j + n]
    return np.bincount(value, minlength=1 << m)


def serial_test(bits, m=16):
    """Равномерность частот всех m-битных шаблонов; возвращает два p-значения."""
    n = len(bits)
    c_m = _window_counts(bits, m)
    # частоты более коротких шаблонов получаются суммированием пар соседних (последний бит отбрасывается)
    c_m1 = c_m.reshape(-1, 2).sum(axis=1)
    c_m2 = c_m1.reshape(-1, 2).sum(axis=1)

    def psi_sq(counts, k):
        return (2.0 ** k / n) * float((counts.astype(np.float64) ** 2).sum()) - n

    psi_m, psi_m1, psi_m2 = psi_sq(c_m, m), psi_sq(c_m1, m - 1), psi_sq(c_m2, m - 2)
    delta1 = psi_m - psi_m1
    delta2 = psi_m - 2.0 * psi_m1 + psi_m2
    return igamc(2.0 ** (m - 2), delta1 / 2.0), igamc(2.0 ** (m - 3), delta2 / 2.0)


def approximate_entropy_test(bits, m=10):
    """Сравнение частот m- и (m+1)-битных шаблонов."""
    n = len(bits)
    c_m1 = _window_counts(bits, m + 1)
    c_m = c_m1.reshape(-1, 2).sum(axis=1)

    def phi(counts):
        p = counts[counts > 0] / n
        return float((p * np.log(p)).sum())

    apen = phi(c_m) - phi(c_m1)
    chi2 = 2.0 * n * (math.log(2.0) - apen)
    return igamc(2.0 ** (m - 1), chi2 / 2.0)


# ----------------------------------------------------------------------
# 13. Тест кумулятивных сумм
# ----------------------------------------------------------------------

def _cdiv(a, b):
    """Целочисленное деление с отсечением к нулю (как в C, на котором написан эталонный код NIST)."""
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q


def _cusum_p_value(n, z):
    sqrt_n = math.sqrt(n)
    total1 = 0.0
    # границы суммирования считаются по правилам C, иначе на малых n p-значение чуть отличается от документа
    for k in range(_cdiv(_cdiv(-n, z) + 1, 4), _cdiv(_cdiv(n, z) - 1, 4) + 1):
        total1 += _phi((4 * k + 1) * z / sqrt_n) - _phi((4 * k - 1) * z / sqrt_n)
    total2 = 0.0
    for k in range(_cdiv(_cdiv(-n, z) - 3, 4), _cdiv(_cdiv(n, z) - 1, 4) + 1):
        total2 += _phi((4 * k + 3) * z / sqrt_n) - _phi((4 * k + 1) * z / sqrt_n)
    return 1.0 - total1 + total2


def cumulative_sums_test(bits):
    """Максимальное отклонение случайного блуждания; возвращает (прямой, обратный) режимы."""
    n = len(bits)
    x = 2 * bits.astype(np.int64) - 1
    forward = int(np.abs(np.cumsum(x)).max())
    backward = int(np.abs(np.cumsum(x[::-1])).max())
    return _cusum_p_value(n, forward), _cusum_p_value(n, backward)


# ----------------------------------------------------------------------
# 14. Тест случайных экскурсий и 15. его вариант
# ----------------------------------------------------------------------

def _walk(bits):
    """Блуждание с нулём в начале и в конце; J - число возвращений в ноль (циклов)."""
    s = np.concatenate(([0], np.cumsum(2 * bits.astype(np.int64) - 1), [0]))
    return s, int(np.count_nonzero(s == 0)) - 1


def random_excursions_test(bits, min_cycles=MIN_CYCLES):
    """8 p-значений (состояния -4..-1, 1..4) либо None, если циклов меньше min_cycles."""
    s, J = _walk(bits)
    if J < min_cycles:
        return None
    cycle_id = np.cumsum(s == 0)           # номер цикла для каждой позиции блуждания
    result = []
    for x in (-4, -3, -2, -1, 1, 2, 3, 4):
        visits = np.bincount(cycle_id[s == x], minlength=J + 2)[1:J + 1]
        nu = np.bincount(np.minimum(visits, 5), minlength=6)     # циклы с k посещениями x
        ax = abs(x)
        pi = ([1.0 - 1.0 / (2 * ax)]
              + [(1.0 / (4 * ax * ax)) * (1.0 - 1.0 / (2 * ax)) ** (k - 1) for k in range(1, 5)]
              + [(1.0 / (2 * ax)) * (1.0 - 1.0 / (2 * ax)) ** 4])
        chi2 = sum((nu[k] - J * pi[k]) ** 2 / (J * pi[k]) for k in range(6))
        result.append(igamc(5 / 2.0, chi2 / 2.0))
    return result


def random_excursions_variant_test(bits, min_cycles=MIN_CYCLES):
    """18 p-значений (состояния -9..-1, 1..9) либо None, если циклов меньше min_cycles."""
    s, J = _walk(bits)
    if J < min_cycles:
        return None
    inside = s[(s >= -9) & (s <= 9)]
    visits = np.bincount(inside + 9, minlength=19)
    result = []
    for x in list(range(-9, 0)) + list(range(1, 10)):
        xi = int(visits[x + 9])
        result.append(math.erfc(abs(xi - J) / math.sqrt(2.0 * J * (4 * abs(x) - 2))))
    return result


# ----------------------------------------------------------------------
# Запуск всех тестов на одном потоке и итоговый анализ
# ----------------------------------------------------------------------

# строки итоговой таблицы в порядке вывода
ROWS = [
    "Frequency", "BlockFrequency", "CumulativeSums (прямой)", "CumulativeSums (обратный)",
    "Runs", "LongestRun", "Rank", "FFT", "NonOverlappingTemplate (148 шаблонов)",
    "OverlappingTemplate", "Universal", "ApproximateEntropy",
    "RandomExcursions (8 состояний)", "RandomExcursionsVariant (18 состояний)",
    "Serial (1)", "Serial (2)", "LinearComplexity",
]


def run_stream(bits):
    """Все 15 тестов на одном потоке; результат - {строка таблицы: [p-значения]}."""
    r = {}
    r["Frequency"] = [frequency_test(bits)]
    r["BlockFrequency"] = [block_frequency_test(bits)]
    forward, backward = cumulative_sums_test(bits)
    r["CumulativeSums (прямой)"] = [forward]
    r["CumulativeSums (обратный)"] = [backward]
    r["Runs"] = [runs_test(bits)]
    r["LongestRun"] = [longest_run_test(bits)]
    r["Rank"] = [binary_matrix_rank_test(bits)]
    r["FFT"] = [dft_test(bits)]
    r["NonOverlappingTemplate (148 шаблонов)"] = list(non_overlapping_template_test(bits).values())
    r["OverlappingTemplate"] = [overlapping_template_test(bits)]
    r["Universal"] = [universal_test(bits)]
    r["ApproximateEntropy"] = [approximate_entropy_test(bits)]
    r["RandomExcursions (8 состояний)"] = random_excursions_test(bits) or []
    r["RandomExcursionsVariant (18 состояний)"] = random_excursions_variant_test(bits) or []
    serial1, serial2 = serial_test(bits)
    r["Serial (1)"] = [serial1]
    r["Serial (2)"] = [serial2]
    r["LinearComplexity"] = [linear_complexity_test(bits)]
    return r


def analyze(p_values, alpha=ALPHA):
    """Итоговый анализ из раздела 4.2 NIST: доля прошедших и равномерность p-значений."""
    m = len(p_values)
    passed = sum(1 for p in p_values if p >= alpha)
    rate = passed / m
    p_hat = 1.0 - alpha
    margin = 3.0 * math.sqrt(p_hat * (1.0 - p_hat) / m)
    bins = [0] * 10
    for p in p_values:
        bins[min(int(p * 10), 9)] += 1
    chi2 = sum((f - m / 10.0) ** 2 / (m / 10.0) for f in bins)
    p_uniform = igamc(9 / 2.0, chi2 / 2.0)
    return {
        "m": m, "passed": passed, "failed": m - passed, "rate": rate,
        "low": p_hat - margin, "high": p_hat + margin,
        "rate_ok": rate >= p_hat - margin,
        "p_uniform": p_uniform, "uniform_ok": p_uniform >= 0.0001, "bins": bins,
    }


def _columns(per_stream, name):
    """p-значения строки таблицы по подтестам: для каждого подтеста - список по потокам.

    Как и в официальном STS, 148 шаблонов, 8 и 18 состояний анализируются по
    отдельности (каждый - по своим потокам): p-значения разных подтестов
    одного потока зависимы, и складывать их в одну кучу нельзя.
    """
    rows = [stream[name] for stream in per_stream if stream[name]]
    return [list(col) for col in zip(*rows)] if rows else []


def format_report(per_stream, source, stream_bits, elapsed):
    """Итоговая таблица в формате markdown."""
    streams = len(per_stream)
    lines = [
        f"Источник данных: {source}",
        f"Потоков: {streams} по {stream_bits} бит, уровень значимости α = {ALPHA}",
        f"Окружение: {platform.platform()}, Python {platform.python_version()}, "
        f"numpy {np.__version__}, время счёта {elapsed:.0f} с",
        "",
        "| Тест | Подтестов | Потоков на подтест | Мин. доля прошедших | Допустимая доля | "
        "Мин. P-значение равномерности | Подтестов не пройдено | Результат |",
        "|---|---|---|---|---|---|---|---|",
    ]
    failed_rows = 0
    for name in ROWS:
        columns = _columns(per_stream, name)
        if not columns:
            lines.append(f"| {name} | 0 | 0 | н/д | н/д | н/д | н/д | не применим (мало циклов) |")
            continue
        results = [analyze(col) for col in columns]
        bad = sum(1 for a in results if not (a["rate_ok"] and a["uniform_ok"]))
        worst = min(results, key=lambda a: a["rate"])
        failed_rows += 1 if bad else 0
        lines.append(
            f"| {name} | {len(columns)} | {worst['m']} | {worst['rate']:.4f} | "
            f"{max(worst['low'], 0):.4f} | {min(a['p_uniform'] for a in results):.6f} | "
            f"{bad} | {'пройден' if not bad else 'есть неудачи'} |"
        )
    n_applicable = sum(1 for s in per_stream if s["RandomExcursions (8 состояний)"])
    lines += [
        "",
        f"Строк таблицы с неудачными подтестами: {failed_rows} из {len(ROWS)}.",
        f"Тесты случайных экскурсий применимы к {n_applicable} из {streams} потоков "
        f"(нужно не меньше {MIN_CYCLES} циклов в блуждании).",
    ]
    if streams < 55:
        lines.append("Потоков меньше 55: интервалы и тест равномерности приближённые "
                     "(рекомендация NIST - от 55).")
    return "\n".join(lines)


# ----------------------------------------------------------------------
# Контрольные «плохие» генераторы: тесты обязаны их отвергать
# ----------------------------------------------------------------------

CONTROLS = ["zeros", "alternating", "biased", "lcg"]


def make_control(name, nbits, seed=1):
    if name == "zeros":
        return np.zeros(nbits, dtype=np.uint8)
    if name == "alternating":
        return (np.arange(nbits) % 2).astype(np.uint8)
    if name == "biased":                   # единиц на 1 % больше, чем нулей
        return (np.random.default_rng(seed).random(nbits) < 0.51).astype(np.uint8)
    if name == "lcg":                      # младший байт линейного конгруэнтного генератора
        x = 1
        out = bytearray((nbits + 7) // 8)
        for i in range(len(out)):
            x = (1103515245 * x + 12345) & 0x7FFFFFFF
            out[i] = x & 0xFF
        return bits_from_bytes(bytes(out))[:nbits]
    raise ValueError("неизвестный контрольный генератор: " + name)


# ----------------------------------------------------------------------
# Командная строка
# ----------------------------------------------------------------------

def _csv_lines(per_stream):
    yield "stream,test,index,p_value"
    for si, stream in enumerate(per_stream):
        for name in ROWS:
            for pi, p in enumerate(stream[name]):
                yield f"{si},{name},{pi},{p:.8f}"


def main(argv=None):
    parser = argparse.ArgumentParser(description="15 тестов NIST SP 800-22 (собственная реализация)")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--input", help="двоичный файл с данными генератора")
    source.add_argument("--control", choices=CONTROLS, help="синтетический плохой генератор")
    parser.add_argument("--stream-bits", type=int, default=STREAM_BITS, help="длина потока в битах")
    parser.add_argument("--streams", type=int, default=0, help="сколько потоков взять (по умолчанию все)")
    parser.add_argument("--jobs", type=int, default=os.cpu_count() or 1, help="число процессов")
    parser.add_argument("--output", help="сохранить итоговую таблицу в файл (UTF-8)")
    parser.add_argument("--csv", help="сохранить все p-значения в CSV")
    args = parser.parse_args(argv)

    if args.input:
        with open(args.input, "rb") as f:
            bits = bits_from_bytes(f.read())
        label = f"файл {os.path.basename(args.input)} ({len(bits) // 8} байт)"
    else:
        count = args.streams or 5
        bits = make_control(args.control, count * args.stream_bits)
        label = f"контрольный генератор '{args.control}'"

    total = len(bits) // args.stream_bits
    if args.streams:
        total = min(total, args.streams)
    if total == 0:
        parser.error("данных меньше одного потока; уменьшите --stream-bits или возьмите файл побольше")
    chunks = [bits[i * args.stream_bits:(i + 1) * args.stream_bits] for i in range(total)]

    start = time.perf_counter()
    per_stream = []
    with ProcessPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        for i, result in enumerate(pool.map(run_stream, chunks), 1):
            per_stream.append(result)
            print(f"поток {i}/{total} готов, прошло {time.perf_counter() - start:.0f} с",
                  file=sys.stderr, flush=True)
    elapsed = time.perf_counter() - start

    report = format_report(per_stream, label, args.stream_bits, elapsed)
    print(report)
    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report + "\n")
    if args.csv:
        with open(args.csv, "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(_csv_lines(per_stream)) + "\n")


if __name__ == "__main__":
    main()

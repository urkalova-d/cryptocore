"""Модуль криптостойкого генератора случайных чисел """
import os


def generate_random_bytes(num_bytes: int) -> bytes:
    """возвращает num_bytes криптостойких случайных байт"""
    if num_bytes < 0:
        raise ValueError("num_bytes must be non-negative")

    try:
        return os.urandom(num_bytes)
    except NotImplementedError as exc:
        # os.urandom документированно кидает NotImplementedError, если на
        # данной платформе не нашлось подходящего источника энтропии
        raise RuntimeError(
            "Secure random number generator is not available on this platform"
        ) from exc

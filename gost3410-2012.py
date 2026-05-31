# -*- coding: utf-8 -*-
"""
==========================================================
РЕАЛИЗАЦИЯ ЭЛЕКТРОННОЙ ЦИФРОВОЙ ПОДПИСИ
ПО ГОСТ Р 34.10-2012
==========================================================

Функциональность:
1. Генерация ключевой пары (d, Q)
2. Ручной ввод закрытого ключа
3. Формирование подписи (по файлу или по введённому хэшу)
4. Проверка подписи (по файлу или по введённому хэшу)

Используется:
- Хэш-функция ГОСТ Р 34.11-2012 (Стрибог, 256 бит)
  через библиотеку gostcrypto (допускается заданием).
- Все остальные операции реализованы вручную:
  арифметика на эллиптической кривой,
  расширенный алгоритм Евклида,
  быстрое умножение точки на число.

Установка зависимости:
    pip install gostcrypto

ВАЖНО:
Данная реализация является учебной.
"""

import os
import gostcrypto


# ============================================================
# ХЭШ-ФУНКЦИЯ ГОСТ Р 34.11-2012 (Стрибог-256)
# ============================================================

class GOST34112012256:
    def __init__(self, data=b""):
        self._h = gostcrypto.gosthash.new("streebog256")
        if data:
            self._h.update(data)

    def update(self, data):
        self._h.update(data)

    def digest(self):
        return bytes(self._h.digest())


# ============================================================
# ПАРАМЕТРЫ ЭЛЛИПТИЧЕСКОЙ КРИВОЙ
# ============================================================
# Кривая в форме Вейерштрасса:  y^2 ≡ x^3 + a*x + b  (mod p)
#
# Текущие значения соответствуют контрольному примеру
# из приложения А ГОСТ Р 34.10-2012. При необходимости
# их можно заменить на любой другой набор параметров —
# программа продолжит работать корректно.

P  = 0x8000000000000000000000000000000000000000000000000000000000000431
A  = 0x0000000000000000000000000000000000000000000000000000000000000007
B  = 0x5FBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E
Q  = 0x8000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3
PX = 0x0000000000000000000000000000000000000000000000000000000000000002
PY = 0x08E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8


# ============================================================
# АРИФМЕТИКА ПО МОДУЛЮ
# ============================================================

def extended_gcd(a, b):
    """
    Расширенный алгоритм Евклида.
    Возвращает (g, x, y) такие, что a*x + b*y = g = gcd(a, b).
    """
    if b == 0:
        return a, 1, 0
    g, x1, y1 = extended_gcd(b, a % b)
    x = y1
    y = x1 - (a // b) * y1
    return g, x, y


def mod_inverse(a, m):
    """
    Нахождение обратного элемента по модулю:
        a * x ≡ 1 (mod m)
    """
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise Exception("Обратного элемента не существует")
    return x % m


# ============================================================
# АРИФМЕТИКА ТОЧЕК ЭЛЛИПТИЧЕСКОЙ КРИВОЙ
# ============================================================

def point_add(P1, P2):
    """
    Сложение двух точек эллиптической кривой по модулю p.
    """
    if P1 is None:
        return P2
    if P2 is None:
        return P1

    x1, y1 = P1
    x2, y2 = P2

    if x1 == x2 and (y1 + y2) % P == 0:
        return None

    if x1 == x2 and y1 == y2:
        num = (3 * x1 * x1 + A) % P
        den = mod_inverse((2 * y1) % P, P)
        lam = (num * den) % P
    else:
        num = (y2 - y1) % P
        den = mod_inverse((x2 - x1) % P, P)
        lam = (num * den) % P

    x3 = (lam * lam - x1 - x2) % P
    y3 = (lam * (x1 - x3) - y1) % P

    return (x3, y3)


def point_mul(k, point):
    """
    Умножение точки на число методом "удвоения и сложения".
    """
    result = None
    addend = point

    while k > 0:
        if k & 1:
            result = point_add(result, addend)
        addend = point_add(addend, addend)
        k >>= 1

    return result


# ============================================================
# ХЭШИРОВАНИЕ ФАЙЛА
# ============================================================

def hash_file(filename):
    """
    Хэширование файла блоками. Возвращает целое число.
    ГОСТ Р 34.11-2012 выдаёт хэш в little-endian порядке байтов.
    """
    hasher = GOST34112012256()
    with open(filename, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            hasher.update(chunk)
    return int.from_bytes(hasher.digest(), 'little')


# ============================================================
# ГЕНЕРАЦИЯ КЛЮЧЕВОЙ ПАРЫ
# ============================================================

def generate_keys():
    """
    Генерация ключевой пары:
        d — случайное число, 0 < d < q (закрытый ключ)
        Q = d * P                       (открытый ключ)
    """
    while True:
        d = int.from_bytes(os.urandom(32), 'big') % Q
        if 0 < d < Q:
            break

    base = (PX, PY)
    Q_point = point_mul(d, base)

    return d, Q_point


# ============================================================
# ФОРМИРОВАНИЕ ПОДПИСИ (с выводом промежуточных значений)
# ============================================================

def sign_hash(e, d, k=None, verbose=True):
    """
    Формирование подписи по уже вычисленному хэшу e.

    e — хэш сообщения как число
    d — закрытый ключ
    k — одноразовое число (если None, генерируется случайно).
        Можно задать явно, чтобы воспроизвести пример из ГОСТа.
    verbose — печатать промежуточные значения.
    """
    e_input = e
    e = e % Q
    if e == 0:
        e = 1

    base = (PX, PY)

    while True:
        if k is None:
            k_use = int.from_bytes(os.urandom(32), 'big') % Q
        else:
            k_use = k % Q

        if k_use == 0:
            if k is not None:
                raise Exception("Заданное k равно 0 по модулю q")
            continue

        C = point_mul(k_use, base)
        x_c, y_c = C

        r = x_c % Q
        if r == 0:
            if k is not None:
                raise Exception("Заданное k даёт r = 0")
            continue

        s = (r * d + k_use * e) % Q
        if s == 0:
            if k is not None:
                raise Exception("Заданное k даёт s = 0")
            continue

        if verbose:
            print("\n--- Промежуточные значения подписи ---")
            print("Хэш e (исходный):", hex(e_input))
            print("Хэш e (mod q)   :", hex(e))
            print("k               :", hex(k_use))
            print("C = k*P, x_C    :", hex(x_c))
            print("C = k*P, y_C    :", hex(y_c))
            print("r = x_C mod q   :", hex(r))
            print("s = (r*d + k*e) :", hex(s))
            print("---------------------------------------")

        return r, s


# ============================================================
# ПРОВЕРКА ПОДПИСИ (с выводом промежуточных значений)
# ============================================================

def verify_hash(e, r, s, Q_point, verbose=True):
    """
    Проверка подписи (r, s) для заданного хэша e
    и открытого ключа Q.
    """
    if not (0 < r < Q and 0 < s < Q):
        if verbose:
            print("Подпись не проходит проверку диапазона: 0 < r,s < q.")
        return False

    e_input = e
    e = e % Q
    if e == 0:
        e = 1

    v = mod_inverse(e, Q)
    z1 = (s * v) % Q
    z2 = ((-r) * v) % Q

    base = (PX, PY)

    p1 = point_mul(z1, base)
    p2 = point_mul(z2, Q_point)
    C = point_add(p1, p2)

    if C is None:
        if verbose:
            print("C' — бесконечно удалённая точка. Подпись неверна.")
        return False

    R = C[0] % Q

    if verbose:
        print("\n--- Промежуточные значения проверки ---")
        print("Хэш e (исходный):", hex(e_input))
        print("Хэш e (mod q)   :", hex(e))
        print("v = e^(-1) mod q:", hex(v))
        print("z1 = s*v mod q  :", hex(z1))
        print("z2 = -r*v mod q :", hex(z2))
        print("C' = z1*P + z2*Q,")
        print("  x_C'          :", hex(C[0]))
        print("  y_C'          :", hex(C[1]))
        print("R = x_C' mod q  :", hex(R))
        print("Эталон r        :", hex(r))
        print("Подпись верна?  :", R == r)
        print("---------------------------------------")

    return R == r


# ============================================================
# СОХРАНЕНИЕ И ЗАГРУЗКА КЛЮЧЕЙ / ПОДПИСИ
# ============================================================

def save_private_key(filename, d):
    with open(filename, "w") as f:
        f.write(hex(d))


def load_private_key(filename):
    with open(filename, "r") as f:
        return int(f.read().strip(), 16)


def save_public_key(filename, Q_point):
    x, y = Q_point
    with open(filename, "w") as f:
        f.write(hex(x) + "\n")
        f.write(hex(y) + "\n")


def load_public_key(filename):
    with open(filename, "r") as f:
        lines = f.read().strip().split("\n")
        x = int(lines[0].strip(), 16)
        y = int(lines[1].strip(), 16)
        return (x, y)


def save_signature(filename, r, s):
    with open(filename, "w") as f:
        f.write(hex(r) + "\n")
        f.write(hex(s) + "\n")


def load_signature(filename):
    with open(filename, "r") as f:
        lines = f.read().strip().split("\n")
        r = int(lines[0].strip(), 16)
        s = int(lines[1].strip(), 16)
        return r, s


# ============================================================
# ВСПОМОГАТЕЛЬНОЕ: получение хэша от пользователя
# ============================================================

def get_hash_from_user(action_name):
    """
    Спрашивает у пользователя источник хэша:
      1) реальный файл (хэшируется Стрибог-256)
      2) ручной ввод hex-числа (для сверки с эталонными примерами)

    Возвращает кортеж (e, описание_источника).
    """
    print(f"\nИсточник хэша для {action_name}:")
    print("  1. Хэш реального файла (ГОСТ Р 34.11-2012)")
    print("  2. Ввести хэш вручную (для сверки с эталоном)")
    src = input("Выберите (1/2): ").strip()

    if src == "1":
        path = input("Путь к файлу: ").strip()
        e = hash_file(path)
        print("Вычисленный хэш e:", hex(e))
        return e, f"файл '{path}'"

    elif src == "2":
        raw = input("Введите хэш e (hex, с 0x или без): ").strip()
        if raw.lower().startswith("0x"):
            e = int(raw, 16)
        else:
            e = int(raw, 16)
        return e, "ручной ввод"

    else:
        raise ValueError("Неверный выбор источника хэша.")


# ============================================================
# ИНТЕРАКТИВНОЕ МЕНЮ
# ============================================================

def main():
    """
    Главное меню программы.
    """
    while True:
        print("\n===== ГОСТ Р 34.10-2012 =====")
        print("1. Сгенерировать ключевую пару")
        print("2. Ввести закрытый ключ вручную")
        print("3. Сформировать подпись")
        print("4. Проверить подпись")
        print("0. Выход")

        choice = input("Выберите действие: ").strip()

        # ----------------------------------
        # Генерация ключей
        # ----------------------------------
        if choice == "1":
            d, Q_point = generate_keys()

            print("\nЗакрытый ключ d:")
            print(hex(d))
            print("\nОткрытый ключ Q = (x, y):")
            print("x =", hex(Q_point[0]))
            print("y =", hex(Q_point[1]))

            save = input("\nСохранить ключи в файлы? (y/n): ").strip().lower()
            if save == "y":
                priv = input("Файл закрытого ключа: ").strip()
                pub  = input("Файл открытого ключа: ").strip()
                save_private_key(priv, d)
                save_public_key(pub, Q_point)
                print("Ключи сохранены.")

        # ----------------------------------
        # Ручной ввод закрытого ключа
        # ----------------------------------
        elif choice == "2":
            raw = input("Введите закрытый ключ d (hex или dec): ").strip()
            if raw.lower().startswith("0x"):
                d = int(raw, 16)
            else:
                d = int(raw)

            if not (0 < d < Q):
                print("Ошибка: d должно удовлетворять 0 < d < q.")
                continue

            base = (PX, PY)
            Q_point = point_mul(d, base)

            print("\nСоответствующий открытый ключ Q:")
            print("x =", hex(Q_point[0]))
            print("y =", hex(Q_point[1]))

            save = input("\nСохранить ключи в файлы? (y/n): ").strip().lower()
            if save == "y":
                priv = input("Файл закрытого ключа: ").strip()
                pub  = input("Файл открытого ключа: ").strip()
                save_private_key(priv, d)
                save_public_key(pub, Q_point)
                print("Ключи сохранены.")

        # ----------------------------------
        # Формирование подписи
        # ----------------------------------
        elif choice == "3":
            # 1) Источник хэша: файл или ручной ввод
            try:
                e, src = get_hash_from_user("подписи")
            except Exception as ex:
                print("Ошибка:", ex)
                continue

            # 2) Закрытый ключ
            keyfile = input("Файл закрытого ключа: ").strip()
            d = load_private_key(keyfile)

            # 3) Опционально: фиксированное k (для сверки с ГОСТом)
            k_raw = input(
                "Задать k вручную (hex, для сверки с эталоном)? "
                "Пустая строка — случайное k: "
            ).strip()
            k = None
            if k_raw:
                if k_raw.lower().startswith("0x"):
                    k = int(k_raw, 16)
                else:
                    k = int(k_raw, 16)

            # 4) Подпись
            r, s = sign_hash(e, d, k=k)

            print("\nИтоговая подпись (источник:", src + "):")
            print("r =", hex(r))
            print("s =", hex(s))

            # 5) Сохранение
            save = input(
                "\nСохранить подпись в файл? (y/n): "
            ).strip().lower()
            if save == "y":
                sigfile = input("Файл для сохранения подписи: ").strip()
                save_signature(sigfile, r, s)
                print(f"Подпись сохранена в {sigfile}.")

        # ----------------------------------
        # Проверка подписи
        # ----------------------------------
        elif choice == "4":
            # 1) Источник хэша
            try:
                e, src = get_hash_from_user("проверки")
            except Exception as ex:
                print("Ошибка:", ex)
                continue

            # 2) Подпись: файл или ручной ввод
            print("\nИсточник подписи:")
            print("  1. Файл подписи")
            print("  2. Ввести r и s вручную")
            sig_src = input("Выберите (1/2): ").strip()

            if sig_src == "1":
                sigfile = input("Файл подписи: ").strip()
                r, s = load_signature(sigfile)
            elif sig_src == "2":
                r_raw = input("Введите r (hex): ").strip()
                s_raw = input("Введите s (hex): ").strip()
                r = int(r_raw, 16)
                s = int(s_raw, 16)
            else:
                print("Неверный выбор.")
                continue

            # 3) Открытый ключ
            keyfile = input("Файл открытого ключа: ").strip()
            Q_point = load_public_key(keyfile)

            # 4) Проверка
            ok = verify_hash(e, r, s, Q_point)

            print("\nИсточник хэша:", src)
            if ok:
                print("Подпись ВЕРНА.")
            else:
                print("Подпись НЕВЕРНА.")

        elif choice == "0":
            break

        else:
            print("Ошибка ввода!")


# ============================================================
# ТОЧКА ВХОДА
# ============================================================

if __name__ == "__main__":
    main()
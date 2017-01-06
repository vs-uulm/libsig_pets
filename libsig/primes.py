import gmpy2 as gm
from gmpy2 import mpz, is_prime
from random import SystemRandom

""" generation of primes
from https://github.com/Chronic-Dev/libgcrypt/blob/master/cipher/primegen.c#L753
"""


def _prime_check_count(bit_count):
    """
    from openssl https://github.com/openssl/openssl/blob/6f0ac0e2f27d9240516edb9a23b7863e7ad02898/include/openssl/bn.h#L121
    :param bit_count:
    :return:
    """
    checks = {
        1300: 2,
        850: 3,
        650: 4,
        550: 5,
        450: 6,
        400: 7,
        350: 8,
        300: 9,
        250: 12,
        200: 15,
        150: 18,
        100: 27
    }
    for size, count in checks.items():
        if bit_count >= size:
            return count


def _prime_generator_next_prime(seed, bit_count):
    """
    alternative method for prime search, just for reference.
    :param seed:
    :param bit_count:
    :return:
    """
    checks = _prime_check_count(bit_count)
    if is_prime(seed, checks):
        yield seed
    prime = seed
    step = 0
    while 20000 > (prime-seed):
        prime = gm.next_prime(prime)
        if step % 10 == 0:
            print(".", end="", flush=True)
        step += 1
        yield prime


def _prime_generator(seed, bit_count, silent=False):
    checks = _prime_check_count(bit_count)
    if is_prime(seed, checks):
        yield seed
    for step in range(0, 20000, 2):
        prime = seed + step
        if not silent and step % 20 == 0 :
            print(".", end="", flush=True)
        if is_prime(prime, checks):
            yield prime


def _prime_seed_generator(bit_count, secret_prime=True):
    sys_rand = SystemRandom()
    while True:
        seed = mpz(sys_rand.getrandbits(bit_count))
        seed = seed.bit_set(bit_count-1)  # ensure bit_count length, by setting highest bit
        if secret_prime:
            seed = seed.bit_set(bit_count-2)  # ensure that prime will be suitable for the RSA modulus
        seed = seed.bit_set(0)  # create an uneven seed
        yield seed


def is_safe_prime(prime):
    """for "safe prime" generation, check that (p-1)/2 is prime.
    Since aprime is odd, We just need to divide by 2
    """
    return gm.is_prime(prime//2)


def gen_prime(bit_count, secret_prime=True, randomlevel=0, extra_check=None, silent=False):
    """
    >>> p = gen_prime(1024 // 2, extra_check=is_safe_prime, silent=True)
    >>> gm.is_prime(p)
    True
    >>> gm.is_prime(p//2)
    True
    """

    min_bits = 16
    if bit_count < min_bits:
        print("can't generate a prime with less than {:d} bits".format(min_bits))
        return None

    for counter, seed in enumerate(_prime_seed_generator(bit_count, secret_prime)):
        for prime in _prime_generator(seed, bit_count, silent):
            if not prime.bit_length() == bit_count:
                continue
            if not extra_check:
                if not silent:
                    print()
                return prime
            elif extra_check(prime):
                if not silent:
                    print()
                return prime
            elif not silent:
                print("/", end="", flush=True)
        if not silent:
            print(":", flush=True)


if __name__ == "__main__":
    p = gen_prime(1024 // 2, extra_check=is_safe_prime)
    print(p)







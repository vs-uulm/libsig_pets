# from gmpy import mpz, is_prime, setbit as bit_set, next_prime
from gmpy2 import mpz, is_prime, bit_set
from libsig import secrets

""" generation of primes
from https://github.com/Chronic-Dev/libgcrypt/blob/master/cipher/primegen.c#L753
"""

safe_prime_1024_1 = mpz(165195723491320276070781388314661969203850281718474434373244184377255543234989828926944838604093072094712871850499619593790369229388254520118976785865223757486364945116449578212404927018534927095601779387234560717995901634286739274946633445438628068352786244592876000571239397727491516595455177480353611868067)
safe_prime_1024_2 = mpz(157862269064439940228510655717005367172381033749718149478446373827553460462372923061777429784196645698005719895063367235052595100578207083662396149553997181007483299532237781653582133926154327260332752894466253219361896539391167392180730877701203825832727693064276062112645179588487253289166027092860869897619)
safe_prime_2048_1 = mpz(31875063319476583474089642096002808986821120019388923550820311241143635510688978606260074843543503406177729419872219920879378521561550721128723409327288344094626341106781088735287836151436862590745544851283429281460660794089948568374839778484814060398861708108831200933525987909325227398182883259169505084369167065660823411144996843994673828630864697567838895733323253393082451689851082041041826040851948931611608019988245083749370267627393937005578783368343755590049940997150576192409347594457043970890265250509809535346754766268393899446480814966824139764465364363653303522872073051059428340389931266289636886972423)
safe_prime_2048_2 = mpz(28279528956854311382393967453636545539930188167062102749496933987991775708347018627270580803309823806119365234883873065755359988782199669134847459237209435424000087073884493312079132564622015178977821522285725219441307093348787566932531883258396964492471036631634785736332476094888956264057006909522141451208726898835554813448189616121674162704637938636518584714801959248702812853220131853421922117430258107368368836901908386727601320910110216519963850643777748034538723380703963471501938067633414455944464136588425261814072585733479498258293168973903021299737360919250029799261615467685929200660563607766827563179079)

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


def _prime_generator(seed, bit_count, verbose=False):
    checks = _prime_check_count(bit_count)
    if is_prime(seed, checks):
        yield seed
    for step in range(0, 20000, 2):
        prime = seed + step
        if verbose and step % 20 == 0 :
            print(".", end="", flush=True)
        if is_prime(prime, checks):
            yield prime


def _prime_seed_generator(bit_count, secret_prime=True):
    while True:
        seed = mpz(secrets.randbits(bit_count))
        seed = bit_set(seed, bit_count-1)  # ensure bit_count length, by setting highest bit
        if secret_prime:
            seed = bit_set(seed, bit_count-2)  # ensure that prime will be suitable for the RSA modulus
        seed = bit_set(seed, 0)  # create an uneven seed
        yield seed


def is_safe_prime(prime):
    """for "safe prime" generation, check that (p-1)/2 is prime.
    Since aprime is odd, We just need to divide by 2
    """
    return is_prime(prime//2)


def gen_prime(bit_count, secret_prime=True, randomlevel=0, extra_check=None, verbose=False):
    """
    >>> p = gen_prime(1024 // 2, extra_check=is_safe_prime)
    >>> is_prime(p)
    1
    >>> is_prime(p//2)
    1
    """

    min_bits = 16
    if bit_count < min_bits:
        print("can't generate a prime with less than {:d} bits".format(min_bits))
        return None

    for counter, seed in enumerate(_prime_seed_generator(bit_count, secret_prime)):
        for prime in _prime_generator(seed, bit_count, verbose):
            if not prime.bit_length() == bit_count:
                continue
            if not extra_check:
                if verbose:
                    print()
                return prime
            elif extra_check(prime):
                if verbose:
                    print()
                return prime
            elif verbose:
                print("/", end="", flush=True)
        if verbose:
            print(":", flush=True)


if __name__ == "__main__":
    p = gen_prime(1024, extra_check=is_safe_prime)
    print(p)







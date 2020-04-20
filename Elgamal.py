import sympy
import random


def gcd(a, b):  # greatest common divisor
    if b == 0:
        return a
    else:
        return gcd(b, a % b)


def euler_func(n):  # Euler's totient function
    count = 0
    for number in range(n):
        if gcd(number, n) == 1:
            count += 1
    return count


def check(root, module):
    if root ** euler_func(module) % module == 1:
        for number in range(1, euler_func(module)):
            if root ** number % module == 1:
                return False
        return True
    else:
        return False


def primitive_root(module):
    root = 1
    while not check(root, module):
        root += 1
    return root


def generate_x(module):
    x = random.randint(1, p)
    while gcd(x, module - 1) != 1:
        x = random.randint(1, p)

    return x


if __name__ == "__main__":

    p = sympy.prime(random.randint(1, 1000))  # nth prime number

    print("Your prime number (p):", p)
    print("Euler function result:", euler_func(p))

    g = primitive_root(p)
    print("Primitive root (a):", g)

    x = generate_x(p)
    print("Private key (x):", x)

    y = g ** x % p
    print("Public key (y):", str(y))

    print("Write your number:")
    m = int(input())

    k = generate_x(p)
    print("Session key (k):", k)

    a = g ** k % p

    b = y ** k * m % p

    print("Your cipher (a, b):", a, b)

    decrypt = b * (a ** (p - 1 - x)) % p
    print("Decrypt:", decrypt)

import textwrap
import random


def formatt(pc1_table, keys_64bits):
    key_56bit = ""

    for index in pc1_table:
        key_56bit += keys_64bits[index - 1]

    return key_56bit


def split(key):
    half = int(len(key) / 2)
    left_keys, right_keys = key[:half], key[half:]

    return left_keys, right_keys


def left_shift(bits, numberofbits):
    shiftedbits = bits[numberofbits:] + bits[:numberofbits]

    return shiftedbits


def compression(pc2_table, keys_56bits):
    key_48bit = ""
    for index in pc2_table:
        key_48bit += keys_56bits[index - 1]

    return key_48bit


def generate_keys(key_64bits):
    tab1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

    tab2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
            55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

    round_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    round_keys = list()

    tab1_out = formatt(tab1, key_64bits)

    l0, r0 = split(tab1_out)

    for round in range(16):
        newL = left_shift(l0, round_shifts[round])
        newR = left_shift(r0, round_shifts[round])

        roundkey = compression(tab2, newL + newR)
        round_keys.append(roundkey)
        l0 = newL
        r0 = newR

    return round_keys


def binary_to_decimal(binarybits):
    decimal = int(binarybits, 2)
    return decimal


ip_table = [58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7]

expansion_table = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                   16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

sbox = [
    # Box-1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    # Box-2

    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],

    # Box-3

    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]

    ],

    # Box-4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],

    # Box-5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    # Box-6

    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]

    ],
    # Box-7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    # Box-8

    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]

]

inverse_permutation_table = [40, 8, 48, 16, 56, 24, 64, 32,
                             39, 7, 47, 15, 55, 23, 63, 31,
                             38, 6, 46, 14, 54, 22, 62, 30,
                             37, 5, 45, 13, 53, 21, 61, 29,
                             36, 4, 44, 12, 52, 20, 60, 28,
                             35, 3, 43, 11, 51, 19, 59, 27,
                             34, 2, 42, 10, 50, 18, 58, 26,
                             33, 1, 41, 9, 49, 17, 57, 25]

permutation_table = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                     2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]


def permutation(ip_table, bin_message):
    permutation_message = ""

    for index in ip_table:
        permutation_message += bin_message[index - 1]

    return permutation_message


def expansion(expansion_table, bits32):
    bits48 = ""
    for index in expansion_table:
        bits48 += bits32[index - 1]

    return bits48


def xor(arg1, arg2):
    xor_result = ""

    for index in range(len(arg1)):
        if arg1[index] == arg2[index]:
            xor_result += '0'
        else:
            xor_result += '1'

    return xor_result


def split_in_6bits(XOR_48bits):
    list_of_6bits = textwrap.wrap(XOR_48bits, 6)

    return list_of_6bits


def get_first_and_last_bit(bits6):
    twobits = bits6[0] + bits6[-1]

    return twobits


def get_middle_four_bit(bits6):
    fourbits = bits6[1:5]

    return fourbits


def decimal_to_binary(decimal):
    binary4bits = bin(decimal)[2:].zfill(4)

    return binary4bits


def sbox_lookup(sboxcount, first_last, middle4):
    d_first_last = binary_to_decimal(first_last)
    d_middle = binary_to_decimal(middle4)

    sbox_value = sbox[sboxcount][d_first_last][d_middle]

    return decimal_to_binary(sbox_value)


def functionF(pre32bits, key48bits):
    result = ""
    expanded_left_half = expansion(expansion_table, pre32bits)
    xor_value = xor(expanded_left_half, key48bits)
    bits6list = split_in_6bits(xor_value)

    for sboxcount, bits6 in enumerate(bits6list):
        first_last = get_first_and_last_bit(bits6)
        middle4 = get_middle_four_bit(bits6)
        sboxvalue = sbox_lookup(sboxcount, first_last, middle4)
        result += sboxvalue

    final32bits = permutation(permutation_table, result)

    return final32bits


def random_key():
    result = ''
    for num in range(64):
        result += str(random.randint(0, 1))
    return result


def des_encrypt():

    print("Write your number: ")
    message = int(input())
    
    print("Your message to encrypt:", message)

    key_64bit = random_key()

    print("This is your key:", key_64bit)

    subkeys = generate_keys(key_64bit)

    bin_message = str(bin(message)[2:])

    zeros = 0

    if len(bin_message) > 64:
        print("Your message is too big, sorry")
        exit(0)
    elif len(bin_message) < 64:
        for i in range(64 - len(bin_message)):
            bin_message += '0'
            zeros += 1

    p_message = permutation(ip_table, bin_message)

    L, R = split(p_message)

    # start rounds
    for round in range(16):
        newR = xor(L, functionF(R, subkeys[round]))
        newL = R
        R = newR
        L = newL
    cipher = permutation(inverse_permutation_table, R + L)

    return cipher, subkeys, zeros


def des_decrypt(message, subkeys, zeros):

    pm = permutation(ip_table, message)
    L, R = split(pm)

    # start rounds
    for round in range(16):
        newR = xor(L, functionF(R, subkeys[round]))
        newL = R
        R = newR
        L = newL

    message = permutation(inverse_permutation_table, R + L)

    return binary_to_decimal(message[:len(message) - zeros])


if __name__ == "__main__":

    cipher, subkeys, zeros = des_encrypt()

    print("Encrypted message:", cipher)
    print("Decrypted message:", des_decrypt(cipher, subkeys[::-1], zeros))

import textwrap
import random


class Key:

    tab1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44,
            36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12,
            4]
    tab2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47,
            55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

    round_shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

    def __init__(self):

        self.round_keys = list()
        self.key_64bit = Key.randomKey()

    @staticmethod
    def randomKey():
        result = ''
        for num in range(64):
            result += str(random.randint(0, 1))
        return result

    def formatt(self):
        key_56bit = ""

        for index in Key.tab1:
            key_56bit += self.key_64bit[index - 1]

        return key_56bit

    @staticmethod
    def left_shift(bits, numberofbits):
        shiftedbits = bits[numberofbits:] + bits[:numberofbits]

        return shiftedbits

    @staticmethod
    def compression(keys_56bits):
        key_48bit = ""
        for index in Key.tab2:
            key_48bit += keys_56bits[index - 1]

        return key_48bit

    def generate_keys(self, format):

        l0, r0 = Prepare.split(format)

        for round in range(16):
            newL = Key.left_shift(l0, Key.round_shifts[round])
            newR = Key.left_shift(r0, Key.round_shifts[round])

            roundkey = Key.compression(newL + newR)

            self.round_keys.append(roundkey)
            l0 = newL
            r0 = newR

    def get_round_keys(self):
        return self.round_keys

    def get_round_keys_reverse(self):
        return self.round_keys[::-1]

    def get_key_64bit(self):
        return self.key_64bit


class F:

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

    permutation_table = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                         2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

    def __init__(self):
        pass

    @staticmethod
    def expansion(bits32):
        bits48 = ""
        for index in F.expansion_table:
            bits48 += bits32[index - 1]

        return bits48

    @staticmethod
    def binary_to_decimal(binarybits):
        decimal = int(binarybits, 2)
        return decimal

    @staticmethod
    def split_in_6bits(XOR_48bits):
        list_of_6bits = textwrap.wrap(XOR_48bits, 6)

        return list_of_6bits

    @staticmethod
    def get_first_and_last_bit(bits6):
        twobits = bits6[0] + bits6[-1]

        return twobits

    @staticmethod
    def get_middle_four_bit(bits6):
        fourbits = bits6[1:5]

        return fourbits

    @staticmethod
    def decimal_to_binary(decimal):
        binary4bits = bin(decimal)[2:].zfill(4)

        return binary4bits

    @staticmethod
    def sbox_lookup(sboxcount, first_last, middle4):
        d_first_last = F.binary_to_decimal(first_last)
        d_middle = F.binary_to_decimal(middle4)

        sbox_value = F.sbox[sboxcount][d_first_last][d_middle]

        return F.decimal_to_binary(sbox_value)

    @staticmethod
    def functionF(pre32bits, key48bits):
        result = ""
        expanded_left_half = F.expansion(pre32bits)
        xor_value = Prepare.xor(expanded_left_half, key48bits)
        bits6list = F.split_in_6bits(xor_value)

        for sboxcount, bits6 in enumerate(bits6list):
            first_last = F.get_first_and_last_bit(bits6)
            middle4 = F.get_middle_four_bit(bits6)
            sboxvalue = F.sbox_lookup(sboxcount, first_last, middle4)
            result += sboxvalue

        final32bits = Prepare.permutation(F.permutation_table, result)

        return final32bits


class Prepare:

    ip_table = [58, 50, 42, 34, 26, 18, 10, 2,
                60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6,
                64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1,
                59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5,
                63, 55, 47, 39, 31, 23, 15, 7]

    inverse_permutation_table = [40, 8, 48, 16, 56, 24, 64, 32,
                                 39, 7, 47, 15, 55, 23, 63, 31,
                                 38, 6, 46, 14, 54, 22, 62, 30,
                                 37, 5, 45, 13, 53, 21, 61, 29,
                                 36, 4, 44, 12, 52, 20, 60, 28,
                                 35, 3, 43, 11, 51, 19, 59, 27,
                                 34, 2, 42, 10, 50, 18, 58, 26,
                                 33, 1, 41, 9, 49, 17, 57, 25]

    @staticmethod
    def split(key):
        half = int(len(key) / 2)
        left_keys, right_keys = key[:half], key[half:]

        return left_keys, right_keys

    @staticmethod
    def permutation(table, bin_message):
        permutation_message = ""

        for index in table:
            permutation_message += bin_message[index - 1]

        return permutation_message

    @staticmethod
    def xor(arg1, arg2):
        xor_result = ""

        for index in range(len(arg1)):
            if arg1[index] == arg2[index]:
                xor_result += '0'
            else:
                xor_result += '1'

        return xor_result


class Crypt:

    def __init__(self, mess):
        self.message = mess
        self.bin_message = str(bin(mess)[2:])
        self.zeros = 0
        self.cipher = ''
        self.L = ''
        self.R = ''

    def get_message(self):
        return self.message

    def get_bin_message(self):
        return self.bin_message

    def get_LR_sum(self):
        return self.L + self.R

    def set_LR(self, permutation):
        self.R, self.L = Prepare.split(permutation)

    def start_rounds(self, sub_keys):
        for round in range(16):
            newR = Prepare.xor(self.L, F.functionF(self.R, sub_keys[round]))
            newL = self.R
            self.R = newR
            self.L = newL

    def get_cipher(self):
        return self.cipher

    def set_cipher(self, c):
        self.cipher = c

    def add_zeros(self):
        if len(self.bin_message) > 64:
            print("Your message is too big, sorry")
            exit(0)
        elif len(self.bin_message) < 64:
            for i in range(64 - len(self.bin_message)):
                self.bin_message += '0'
                self.zeros += 1

    def getText(self, mess):
        return F.binary_to_decimal(mess[:len(mess) - self.zeros])


if __name__ == "__main__":

    print("Write your number:")
    crypto = Crypt(int(input()))
    print("Your message to encrypt:", crypto.get_message())

    key = Key()
    key.generate_keys(key.formatt())

    print("This is your key:", key.get_key_64bit())

    crypto.add_zeros()

    bin_mess = crypto.get_bin_message()

    crypto.set_LR(Prepare.permutation(Prepare.ip_table, bin_mess))
    sub_key = key.get_round_keys()

    crypto.start_rounds(sub_key)

    crypto.set_cipher(Prepare.permutation(Prepare.inverse_permutation_table, crypto.get_LR_sum()))

    print("Encrypted message:", crypto.get_cipher())

    crypto.set_LR(Prepare.permutation(Prepare.ip_table, crypto.cipher))
    sub_key = key.get_round_keys_reverse()

    crypto.start_rounds(sub_key)

    result = Prepare.permutation(Prepare.inverse_permutation_table, crypto.get_LR_sum())
    print("Decrypted message:", crypto.getText(result))
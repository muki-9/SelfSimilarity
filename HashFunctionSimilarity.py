from SHA256 import *
from SM3 import *
import random
import string
import sys


class Similarity:


    def __init__(self, rounds, mode):

        self.mask = \
            '0000000000000000000000000000000000000000000000000000000000000001'
        self.mode = mode
        if self.mode == 'SHA-256':
            self.iv = [0x6a09e667, 0xbb67ae85,0x3c6ef372,
                       0xa54ff53a,0x510e527f, 0x9b05688c,
                       0x1f83d9ab, 0x5be0cd19]
        else:
            self.iv= [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
                      0xa96f30bc,0x163138aa ,0xe38dee4d ,0xb0fb0e4e]
        self.rounds = rounds

    def generate(self):

        return ''.join(random.choice(string.ascii_lowercase)
                       for i in range(4))

    def flatten(self, results):

        return [item for subresults in results
                for item in subresults ]

    def _bin_to_hex(self, data):
        return str(format(int(data, 2), "008x"))

    def bitwise_hex_xor(self, x,y):

        return (hex(int(x, 16) ^ int(y, 16)))\
            .lstrip('0x').zfill(len(x))

    def bitwise_bin_xor(self, x,y):

        return (bin(int(x, 2) ^ int(y, 2))).lstrip('0b').zfill(len(x))

    def writeToFile(self, mask, word, results,xor):

        with open(self.mode + str(mask), 'a') as file:
            initial_ = word + "\t" + self.mode + '\t' + '\t' \
                .join([hex(register)[2:].zfill(8)
                       for register in self.iv]) + '\t'
            file.write(initial_)
            rounds = '\t'.join([hex(int(item, 2))[2:]
                               .zfill(8)
                                for item in self.flatten(results)])
            file.write(rounds)
            file.write("\n")
            xor_initial_ = word + "\t" + self.mode + '\t' + \
                           '\t'.join([hex(int(mask[i:i + 8], 16))[2:]
                                     .zfill(8)
                                      for i in range(0, len(mask), 8)]) \
                           + '\t'
            file.write(xor_initial_)
            xor_rounds = '\t'.join([hex(int(item, 2))[2:].zfill(8)
                                    for item in self.flatten(xor)])
            file.write(xor_rounds)
            file.write("\n")

    def _xor_iv_mask(self, mask):

        initial_vectors_joined = ''.join([hex(register)[2:]
                                          for register in self.iv])
        xor_result = self.bitwise_hex_xor(initial_vectors_joined, mask)

        registers= [hex(int(xor_result[i:i+8], 16))
                    for i in range(0, len(xor_result), 8)]
        return registers

    def check_similarity(self, results, xor_results):

        bits =[26,24,22,18]

        similar = True

        xor_all = []

        for i in range(len(results)):

            xor_diff = [self.bitwise_bin_xor(x, y)
                        for x, y in zip(results[i], xor_results[i])]

            for j in range(len(xor_diff)):

                if not (xor_diff[j].count('0') > bits[i]):
                    similar = False

            if not similar:
                break
            else:

                xor_all.append(xor_diff)

        return similar, xor_all

    def main(self):

        n_results = 0

        while True:

            word= self.generate()

            if self.mode == "SHA-256":

                sha256= SHA256(word, self.rounds)
                results = sha256._encrypt()
            else:
                sm3 = SM3(word, self.rounds)
                results = sm3.encrypt()

            mask = self.mask

            while True:

                new_iv = self._xor_iv_mask(mask)

                if self.mode == "SHA-256":

                    sha256_xor = SHA256(word,
                                        self.rounds, new_iv)
                    xor_results = sha256_xor._encrypt()
                else:
                    sm3_xor = SM3(word, self.rounds, new_iv)
                    xor_results = sm3_xor.encrypt()

                similar, xor = self.check_similarity(results,
                                                     xor_results)


                if similar:

                    self.writeToFile(mask,word,results,xor)

                if(mask.startswith("8")):
                    break

                mask = hex(int(mask,16) << 1)[2:].zfill(64)


sim = Similarity(rounds=4,mode="SM3")
sim.main()























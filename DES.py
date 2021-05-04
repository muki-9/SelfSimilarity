from SBOXKorean import s5_sboxs


class DES:


    def __init__(self, key, data, rounds, version=None):

        self.version= version
        self.L = []
        self.R = []
        self.Keys = [[0] * 48] * rounds



        self.data = data

        if len(key) != 16:

            raise ValueError("Key value should contain 64 bits")

        self.key = key
        self.rounds = rounds

        self.ip = [58, 50, 42, 34, 26, 18, 10, 2,
                 60, 52, 44, 36, 28, 20, 12, 4,
                 62, 54, 46, 38, 30, 22, 14, 6,
                 64, 56, 48, 40, 32, 24, 16, 8,
                 57, 49, 41, 33, 25, 17, 9, 1,
                 59, 51, 43, 35, 27, 19, 11, 3,
                 61, 53, 45, 37, 29, 21, 13, 5,
                 63, 55, 47, 39, 31, 23, 15, 7]


        self.pc1_ = [57, 49, 41, 33, 25, 17, 9,
                1, 58, 50, 42, 34, 26, 18,
                10, 2, 59, 51, 43, 35, 27,
                19, 11, 3, 60, 52, 44, 36,
                63, 55, 47, 39, 31, 23, 15,
                7, 62, 54, 46, 38, 30, 22,
                14, 6, 61, 53, 45, 37, 29,
                21, 13, 5, 28, 20 ,12, 4]

        self.pc2_ = [14, 17, 11, 24, 1, 5,
                3, 28, 15, 6, 21, 10,
                23, 19, 12, 4, 26, 8,
                16, 7, 27, 20, 13, 2,
                41, 52, 31, 37, 47, 55,
                30, 40, 51, 45, 33, 48,
                44, 49, 39, 56, 34, 53,
                46, 42, 50, 36, 29, 32]

        self.permbox_ = [ 16,  7, 20, 21,
                            29, 12, 28, 17,
                             1, 15, 23, 26,
                             5, 18, 31, 10,
                             2,  8, 24, 14,
                            32, 27,  3,  9,
                            19, 13, 30,  6,
                            22, 11,  4, 25 ]


        self.exp_permutation = [32, 1, 2, 3, 4, 5, 4, 5,
                      6, 7, 8, 9, 8, 9, 10, 11,
                      12, 13, 12, 13, 14, 15, 16, 17,
                      16, 17, 18, 19, 20, 21, 20, 21,
                      22, 23, 24, 25, 24, 25, 26, 27,
                      28, 29, 28, 29, 30, 31, 32, 1]


        self.lcs_ = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

        self.final_perm = [40, 8, 48, 16, 56, 24, 64, 32,
                           39, 7, 47, 15, 55, 23, 63, 31,
                           38, 6, 46, 14, 54, 22, 62, 30,
                           37, 5, 45, 13, 53, 21, 61, 29,
                           36, 4, 44, 12, 52, 20, 60, 28,
                           35, 3, 43, 11, 51, 19, 59, 27,
                           34, 2, 42, 10, 50, 18, 58, 26,
                           33, 1, 41, 9, 49, 17, 57, 25]

        self.sboxs = [


            [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
             [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
             [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
             [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

            [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
             [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
             [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
             [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],


            [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
             [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
             [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
             [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

            [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
             [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
             [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
             [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

            [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
             [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
             [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
             [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

            [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
             [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
             [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
             [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

            [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
             [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
             [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
             [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],

            [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
             [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
             [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
             [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

            ]


    def _hex_to_bits(self, data):

        return str(format(int(data, 16), "064b"))

    def _bit_to_hex(self, data):

        return str(format(int(data, 2), "008x"))



    def _dec_to_bits(self,data):

        return str("{0:04b}".format(int(data,10)))



    def __create_subkeys(self, key):

        if len(key) != 56:

            raise ValueError ("Key needs to be 56 bits via PC1")

        curr_key = key
        for round in range(self.rounds):

            L = self._LCS(curr_key[:28], round)
            R = self._LCS(curr_key[28:], round)

            curr_key = L + R
            self.Keys[round] = self._permutation(self.pc2_, curr_key)


    def _permutation(self, table, data):

        permuted_key = ''.join([data[bit-1] for bit in table])

        return permuted_key


    def _LCS(self, data, round):

        shift_number = self.lcs_[round]

        lcs = data[shift_number:] + data[:shift_number]

        return lcs


    def _sbox(self, data):

        if self.version == "S5DES":
            _sboxs = s5_sboxs
        else:
            _sboxs = self.sboxs

        parts = [data[i:i+6] for i in range(0, len(data), 6)]

        result = ""

        for box in range(len(parts)):

            part = parts[box]

            row_= int(part[0] + part[5],2)
            column_ = int(part[1]+ part[2] + part[3]+ part[4],2)

            result += self._dec_to_bits(str(_sboxs[box][row_][column_]))


        return result



    def _round_function(self, subkey,  R):


        exp_result = self._permutation(self.exp_permutation, R)


        xor_ = ''.join(str(ord(a) ^ ord(b)) for a,b in zip(exp_result, subkey))


        sbox_output = self._sbox(xor_)

        perm_output = self._permutation(self.permbox_, sbox_output)

        return perm_output

        # xor2_ = ''.join(str(ord(a) ^ ord(b)) for a,b in zip(perm_output, L))
        #
        # R_output = xor2_
        #
        # output = L_output + R_output
        #
        # return output



    def _encrypt(self):

        key_in_bits = self._hex_to_bits(self.key)

        pc1key = self._permutation(self.pc1_, key_in_bits)

        self.__create_subkeys(pc1key)

        data = self._hex_to_bits(self.data)


        L, R = [None]* (self.rounds+1),[None]* (self.rounds+1)


        L[0] = data[:32]
        R[0] = data[32:]

        for i in range(1, self.rounds):

            L[i] = R[i-1]

            R[i] = self._round_function(self.Keys[i-1], R[i-1])
            # if(i == 6):
            #     print(self.Keys[i-1])

            R[i] = ''.join(str(ord(a) ^ ord(b)) for a,b in zip(R[i], L[i-1]))

            # if(i==5):
            #     print(L[i])
            #     print(R[i])

            # print(self._bit_to_hex(L[i]+ R[i]))

        if(self.rounds == 16):

            L[self.rounds] = self._round_function(self.Keys[self.rounds-1], R[self.rounds-1])
            L[self.rounds] = ''.join(str(ord(a) ^ ord(b)) for a,b in zip(L[self.rounds], L[self.rounds-1]))
            R[self.rounds] = R[self.rounds-1]
        else:

            L[self.rounds] = R[self.rounds - 1]

            R[self.rounds] = self._round_function(self.Keys[self.rounds - 1], R[self.rounds - 1])
            # if(i == 6):
            #     print(self.Keys[i-1])

            R[self.rounds] = ''.join(str(ord(a) ^ ord(b)) for a, b in zip(R[self.rounds], L[self.rounds - 1]))


        return ( ([self._bit_to_hex(value) for value in R[1:]]))




        # result = self._permutation(self.final_perm, (L[self.rounds]+R[self.rounds]))
        # print(hex(int(result,2)))




        # self._round_function(data)
        # # data = self._permutation(self.ip, data)
        # #
        # # for round in range(self.rounds):
        # #
        # #     round_output = self._round_function(self.Keys[round], data)
        # #
        # #     data = round_output
        # #     #
        # #     # print(self._bit_to_hex(data))
        #
        #
        # L = data[32:]
        # R = data[:32]
        #
        # swap_ = L + R
        #
        # final_output = self._bit_to_hex(self._permutation(self.final_perm, swap_))
        # print(final_output)


#
# des = DES("ef331934d9e23415","18aa3147e7b945b5", 4)
#
# print(des._encrypt())









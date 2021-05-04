
class SM3:


    def __init__(self, data, rounds, iv=None):

        self.data = data
        self.words = [""]*68
        self.words_prime= [""]*64

        if rounds is not None:
            self.rounds = rounds
        else:
            self.rounds = 64

        if iv is not None:
            self.initial_registers = iv
        else:
            self.initial_registers = ['7380166f', '4914b2b9', '172442d7', 'da8a0600', 'a96f30bc','163138aa' ,'e38dee4d' ,'b0fb0e4e']

        self.constants = [0x79cc4519, 0x7a879d8a]


    def bin_add(self, *args):

        return bin(sum(int(x, 2) for x in args) % (2 ** 32))[2:].zfill(32)

    def _string_to_binary(self, data):

        return''.join(format(ord(x), '008b') for x in data)

    def _hexstring_to_32bits(self, data):

        return str(format(int(data,16), "032b"))

    def _hex_to_32bits(self, data):

        return str(format(data, "032b"))

    def test_to_hex(self,data):
        return str(format(int(data, 2), "008x"))


    def _bin_to_hex(self, data):
        return str(format(int(data, 2), "016x"))

    def bitwise_xor(self,x,y):

        return ''.join(str(ord(a) ^ ord(b)) for a, b in zip(x, y))

    def bitwise_xor3(self, x, y, z ):

        xor1 = ''.join(str(ord(a) ^ ord(b)) for a, b in zip(x, y))
        return ''.join(str(ord(a) ^ ord(b)) for a, b in zip(xor1, z))

    def _ROTL(self, data, shift):
        rotl = data[shift:] + data[:shift]

        return rotl

    def FFj(self, x, y, z, round):

        if round < 16:
            return self.bitwise_xor3(x, y, z)
        else:
            return bin((int(x, 2) & int(y, 2)) | (int(x, 2) & int(z, 2)) | (int(y, 2) & int(z, 2)))[2:].zfill(32)

    def GGj(self, x, y, z, round):

        if round < 16:
            return self.bitwise_xor3(x, y, z)
        else:
            return bin((int(x, 2) & int(y, 2)) | (~int(x, 2) & int(z, 2)))[2:].zfill(32)

    def P1(self, X):

        return self.bitwise_xor3(X, self._ROTL(X,15), self._ROTL(X,23))

    def P0(self, X):

        return self.bitwise_xor3(X, self._ROTL(X,9), self._ROTL(X,17))


    def create_words(self):

        for i in range(16,68):

            self.words[i] = self.bitwise_xor3(self.P1((self.bitwise_xor3(self.words[i-16], self.words[i-9], self._ROTL(self.words[i-3], 15)))), self._ROTL(self.words[i-13], 7), self.words[i-6])


    def create_words_prime(self):

        for i in range(0,64):

            self.words_prime[i] = self.bitwise_xor(self.words[i], self.words[i+4])


    def compression(self):

        registers_round= []

        a, b, c, d, e, f, g, h = [register for register in self.initial_registers]

        for i in range(self.rounds):

            if i< 16:
                T = self._hex_to_32bits(self.constants[0])
            else:
                T = self._hex_to_32bits(self.constants[1])

            SS1 = self._ROTL(self.bin_add(self._ROTL(a,12), e, self._ROTL(T, i%32)), 7)
            SS2 = self.bitwise_xor(SS1, self._ROTL(a,12))
            TT1 = self.bin_add(self.FFj(a,b,c,i), d, SS2, self.words_prime[i])
            TT2 = self.bin_add(h, self.GGj(e,f,g,i), SS1,self.words[i])
            d = c
            c = self._ROTL(b,9)
            b= a
            a = TT1
            h = g
            g= self._ROTL(f,19)
            f = e
            e = self.P0(TT2)

            temp_registers= [a,b,c,d,e,f,g,h]
            registers_round.append([register for register in temp_registers])


        registers = [a,b,c,d,e,f,g,h]

        return registers, registers_round

    def padding(self, data):

        message_blocks = [data[i:i+448] for i in range(0,len(data), 448)]

        padded_blocks = [""] * len(message_blocks)

        for i in range(len(message_blocks)):

            output  = message_blocks[i] + "1"
            output = output.ljust(448, '0')
            output += "{0:064b}".format(len(message_blocks[i]))
            padded_blocks[i] = output

        return padded_blocks

    def encrypt(self):



        for i in range(len(self.initial_registers)):
            self.initial_registers[i] = self._hexstring_to_32bits(self.initial_registers[i])

        binary_data = self._string_to_binary(self.data)

        padded_blocks = self.padding(binary_data)

        #
        for block in padded_blocks:

            for i in range(16):
                self.words[i] = block[i*32:(i+1)*32]

            self.create_words()
            self.create_words_prime()

            registers, registers_round = self.compression()

            self.initial_registers = [self.bitwise_xor(x,y) for x,y in zip(self.initial_registers, registers)]
        #
        # final_hash = ''.join([register for register in self.initial_registers])

        return registers_round


#
# sm3 = SM3('abc', 64)
# sm3.encrypt()






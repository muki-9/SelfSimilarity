

class SHA256:

    """

    sigma0(x): ROTR(7) + ROTR(18) + SHR (3)
    sigma1(x): ROTR(17) + ROTR(19) + SHR (10)
    SIGMA0(x): ROTR(2) + ROTR(13) + ROTR (22)
    SIGAMA1(x): ROTR(6) + ROTR(11) + ROTR (25)
    Choice(x,y,z): Uses x input to decide whether to choose y or z bit. If bit is 1, then y is 0 then z
    Majority(x,y,z): Whichever bit is majority is taken as bit

    Constants:
    Cube root of first 64 prime numbers

    1. Convert string to ASCII and into binary
    2. Padd to 512 bits (1 to 0's up to 448)
    3. Last 64 bits represent length of message
    4. Message schedule: Break 512 bit block in to 16 words, but need 64 words
    5. So W(t) = sigma1(t-2) + (t-7) + sigma0(t-15) + (t-16) where t is word number
    6. Repeat til create 64 words (t= 63)
    7. Compresion function: Need initalise state registers (a-h) using fractional part of square of first 8 prime numbers muliplied by 2^32 and converted to binary
    8. Take First word and first constant and use to create two temporary words
    9. T1 = SIGMA1(e) + Choice(e,f,g) + h + Constant0 + Word0
    10. T2 = SIGMA0(a) + Majority(a,b,c)
    11. First round: shift all register values down one (not rotational) so a is empty.
    12. Replace a with T1 +T2
    13. Add T1 to e
    14. Repeat for each word (64 rounds)
    15. Take intial hash value and add end result of compression.
    16. Repeat for each message block then concatenate the hex values together

    """


    def __init__(self, data,rounds=None, iv=None,):

        self.data= data
        self.words = [""] * 64
        self.iv = iv

        if rounds is not None:
            self.rounds=rounds
        else:
            self.rounds = 64

        self.constants = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
        ]

        if iv is not None:
            self.initial_registers = iv
        else:
            self.initial_registers = ['6a09e667', 'bb67ae85' ,'3c6ef372', 'a54ff53a', '510e527f', '9b05688c', '1f83d9ab' ,'5be0cd19']

    def _dec_to_binary(self, data):
        return str("{:0>32b}".format(data))

    def _hexstring_to_32bits(self, data):

        return str(format(int(data,16), "032b"))

    def _hex_to_32bits(self, data):

        return str(format(data, "032b"))


    def _bin_to_hex(self, data):
        return str(format(int(data, 2), "016x"))

    def _xor2(self, x, y):

        return ''.join(str(ord(a) ^ ord(b)) for a, b in zip(x, y))

    def _xor3(self, x, y, z):

        xor1 = ''.join(str(ord(a) ^ ord(b)) for a, b in zip(x, y))
        return ''.join(str(ord(a) ^ ord(b)) for a, b in zip(xor1, z))


    def _create_words(self):
        """
        W(t) = sigma1(t-2) + (t-7) + sigma0(t-15) + (t-16) where t is word number
        NOTE: 16 words (0-15) have already been created, need to create W16- W63
        """

        for i in range(16, 64):

            self.words[i] = self.bin_add(self._sigma_1(self.words[i-2]), self.words[i-7], self._sigma_0(self.words[i-15]) ,self.words[i-16])


    def _ROTR(self, data, shift):

        rotr = data[-shift:] + data[:-shift]

        return rotr

    def bin_add(self, *args):

        return bin(sum(int(x, 2) for x in args) % (2 ** 32))[2:].zfill(32)

    def _sigma_0(self, data):

        rotr7 = self._ROTR(data, 7)
        rotr18 = self._ROTR(data, 18)
        shift_r3 = data[:-3].rjust(len(data), '0')

        result = self._xor3(rotr7, rotr18, shift_r3)

        return result

    def _sigma_1(self, data):


        rotr17 = self._ROTR(data, 17)
        rotr19 = self._ROTR(data, 19)
        shift_r10 = data[:-10].rjust(len(data), '0')

        result = self._xor3(rotr17, rotr19, shift_r10)

        return result

    def _upper_sigma_0(self, data):

        rotr2 = self._ROTR(data, 2)
        rotr13 = self._ROTR(data, 13)
        rotr22 = self._ROTR(data, 22)

        result = self._xor3(rotr2, rotr13, rotr22)

        return result

    def _upper_sigma_1(self, data):

        rotr6 = self._ROTR(data, 6)
        rotr11 = self._ROTR(data, 11)
        rotr25 = self._ROTR(data, 25)

        result = self._xor3(rotr6, rotr11, rotr25)

        return result

    def _choice(self, x, y, z):

        return ''.join([y[i] if x[i] == "1" else z[i] for i in range(len(x))])

    def _majority(self, x, y, z):

        return ''.join(["1" if (int(x)+int(y)+int(z))/3 > 0.5 else "0" for x,y,z in zip(x,y,z)])


    def _string_to_binary(self, data):

        return''.join(format(ord(x), '008b') for x in data)

    def _padd(self, data):

        message_blocks = [data[i:i+448] for i in range(0,len(data), 448)]

        padded_blocks = [""] * len(message_blocks)

        for i in range(len(message_blocks)):

            output  = message_blocks[i] + "1"
            output = output.ljust(448, '0')
            output += "{0:064b}".format(len(message_blocks[i]))
            padded_blocks[i] = output

        return padded_blocks


    def _compression(self):
        """
        Initalise register a-h with fractional part of first 8 square numbers fractional
        :return:
        """
        registers_round = []
        registers =  [register for register in self.initial_registers]

        for i in range(self.rounds):

            T1 =  self.bin_add(registers[7], self._upper_sigma_1(registers[4]) ,self._choice(registers[4],registers[5] ,registers[6]), self.words[i], self._hex_to_32bits(self.constants[i]))
            T2 =  self.bin_add(self._upper_sigma_0(registers[0]) ,self._majority(registers[0],registers[1],registers[2]))

            for i in range(len(registers)-1, 0, -1):

                registers[i] = registers[i-1]

            registers[0] = self.bin_add(T1, T2)
            registers[4] = self.bin_add(registers[4],T1)


            registers_round.append([register for register in registers])


        return registers, registers_round

    def _encrypt(self):



        for i in range(len(self.initial_registers)):
            self.initial_registers[i] = self._hexstring_to_32bits(self.initial_registers[i])


        binary_data = self._string_to_binary(self.data)

        padded_blocks = self._padd(binary_data)

        for block in padded_blocks:

            for i in range(16):
                self.words[i] = block[i*32:(i+1)*32]

            self._create_words()
            registers, registers_rounds = self._compression()


            self.initial_registers = [self.bin_add(x,y) for x,y in zip(self.initial_registers, registers)]


        # final_hash = ''.join([register for register in self.initial_registers])
        # print([self._bin_to_hex(final_hash)])
        # return registers_rounds
        return registers_rounds


sha256= SHA256("znli")
sha256._encrypt()
#



























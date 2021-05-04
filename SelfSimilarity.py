from DES import *
# from SHA256 import *
import random as rand
import string
import itertools
import time


class SelfSimilarity:

    def __init__(self, rounds, mode= None, key=None, data=None):
        """

        :param rounds: Number of rounds to conduct self simiarlity for
        :param mode: DES or S5DES
        :param key: 64 bit key if provided
        :param data: 64 bit data if provided
        """


        self.key = key
        self.data=data
        self.start = time.time()
        self.timearray = []
        self.rounds = rounds
        self.mode = mode
        self.bits = [28, 26, 23, 18]


    def getResults(self, key, rounds, data, array):

        """
        Iterate through many random permutations of
        masking and conduct DES for certain number of rounds
        Adds to list of results if similar.
        """

        counter_without_result = 0
        results= {}
        while True:

            if counter_without_result > 2 ** 17:
                break

            curr_len = len(results)

            num1, num2 = self._get_xor_hex(array, results)
            hex_value = num1 + num2


            new_data = self.bitwise_xor(data, hex_value)
            des_ = DES(key, new_data, self.rounds, self.mode)

            new_rounds = des_._encrypt()

            results = self.check_similarity(results, rounds,
                                            new_rounds, hex_value)

            if len(results) > curr_len:

                counter_without_result = 0
            else:
                counter_without_result += 1

        return results

    def getXORSimiarlity(self, results):

        """

        :param results: List of results which are similar
        to main encryption
        :return: Triples where 3 encryptions are similar
         to each other
        """

        sim_results = []

        for x, y in itertools.combinations(results, 2):

            similar = True

            for i in range(0, 4):

                or_result = self.bitwise_xor(results[x][i],
                                             results[y][i])

                if not (bin(int(or_result, 16))[2:]
                                .zfill(32)
                                .count('0') > self.bits[i]):
                    similar = False
                    break

            if similar:
                sim_results.append((x, results[x]))
                sim_results.append((y, results[y]))

        return sim_results

    def generate(self):

        minDES = 0
        maxDES = 2 ** 64

        key = str(format(rand.randint(minDES, maxDES), "016x"))
        data = str(format(rand.randint(minDES, maxDES), "016x"))

        return [key,data]


    def bitwise_xor(self,x, y):

        return (hex(int(x, 16) ^ int(y, 16)))\
            .lstrip('0x').zfill(len(x))

    def _get_xor_hex(self, array, results):


        num1 = str(format(rand.choice(array), '008x'))
        num2 = str(format(rand.choice(array), '008x'))

        if (num1 and num2 == '00000000') \
                or (num1+num2) in results.keys():
           num1, num2 =  self._get_xor_hex(array, results)

        return num1, num2


    def check_similarity(self, results, rounds,
                         new_rounds, hex_value):

        """

        :return: List of results which contains
        similar results
        """

        xor_diff = [self.bitwise_xor(x, y)
                    for x, y in zip(rounds, new_rounds)]

        similar = True
        for i in range(0,4):

            if not (bin(int(xor_diff[i],16))[2:]
                            .zfill(32).count('0') > self.bits[i]):
                similar = False
                break

        if similar:
            results[hex_value] = xor_diff

        return results


    def main(self):

        permutations = 2**25
        array = []
        for i in range(permutations):
            if str(bin(i)).count('1') < 4:
                array.append(i)
        print(array[:10])
        num_results = 0

        while True:

            key, data = self.generate()

            des = DES(key,data, self.rounds, self.mode)
            rounds = des._encrypt()

            results = self.getResults(key, rounds,
                                      data, array)

            sim_results = self.getXORSimiarlity(results)

            if len(sim_results) !=0:

                with open("S5DESTriples" + data, 'a') \
                        as file_out:

                    for i in range(len(sim_results)):

                        if i %2 == 0:
                            num_results += 1
                            print("S5DES:" + str(num_results))
                            initial_ = key + "\t" + self.mode + '\t' \
                                       + data[:8] + '\t' + data[8:] + '\t'
                            line_w_tabs = "\t".join(rounds) + '\n'
                            file_out.write(initial_)
                            file_out.write(line_w_tabs)


                        initial_ = key + "\t" + self.mode + '\t' \
                                   + sim_results[i][0][:8] + '\t'\
                                   + sim_results[i][0][8:] + '\t'
                        line_w_tabs = "\t".join(sim_results[i][1]) + '\n'
                        file_out.write(initial_)
                        file_out.write(line_w_tabs)
                        end_time = time.time()
                        self.timearray.append(end_time-self.start)


ss= SelfSimilarity(4, "S5DES")

try:

    ss.main()
except KeyboardInterrupt:

    print(ss.timearray)




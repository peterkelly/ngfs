import struct

# https://en.wikipedia.org/wiki/Linear_congruential_generator#cite_note-Steele20-3
#
# Parameters from Microsoft Visual/Quick C/C++
# m = 2^32
# a = 214013
# c = 2531011

def lcg(a, c, seed):
    while True:
        seed = (((a * seed) & 0xFFFFFFFF) + c) & 0xFFFFFFFF

        yield seed


def main():
    count = 0
    a = 214013
    c = 2531011

    seed = 12345
    frequency = [0] * 32
    for v in lcg(a, c, seed):
        print("%08x " % (v), end="")
        for i in range(0, 32):
            if (v >> (31 - i)) & 1:
                print("1", end="")
                frequency[i] += 1
            else:
                print("0", end="")
        print()
        count += 1
        if count == 100000:
            break
    for i in range(0, 32):
        print("frequency[%02d] = %d" % (i, frequency[i]))

main()

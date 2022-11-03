import struct, codecs, hashlib


# Циклический сдвиг вправо
def ror(val, r_bits, max_bits):
    rb = r_bits % max_bits
    hv = 2**max_bits-1
    return val >> rb & hv | val << (max_bits - rb) & hv


def sha256_sum(message):
    # Константа для операции сложения по модулю 2**32
    MOD32 = 2**32
    # Инициализация переменных (первые 32 бита дробных частей квадратных корней первых восьми простых чисел [от 2 до 19]):
    h0 = 0x6A09E667
    h1 = 0xBB67AE85
    h2 = 0x3C6EF372
    h3 = 0xA54FF53A
    h4 = 0x510E527F
    h5 = 0x9B05688C
    h6 = 0x1F83D9AB
    h7 = 0x5BE0CD19

    # Таблица констант (первые 32 бита дробных частей кубических корней первых 64 простых чисел [от 2 до 311]):
    k = (0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
         0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
         0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
         0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
         0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
         0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
         0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
         0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2)

    # Предварительная обработка (дополнение исходного сообщения):
    m_len = len(message)
    p_len = 64 - m_len % 64 - 8
    m = message + (0b10000000).to_bytes(p_len, byteorder='little', signed=False) + (m_len * 8).to_bytes(8, byteorder='big', signed=False)

    # Далее сообщение обрабатывается последовательными порциями по 512 бит:
    block = []

    # Разбить сообщение на блоки по 512 бит
    for j in range(len(m) // 64):
        block.append(m[j*64:(j+1)*64])
        # Каждый блок разбить на 16 слов длиной 32 бита (с порядком байтов от старшего к младшему внутри слова):
        w = [0 for w in range(64)]
        for i in range(16):
            w[i] = int.from_bytes(block[j][i*4:(i+1)*4], byteorder='big', signed=False)
        # Сгенерировать дополнительные 48 слов:
        for i in range(16,64):
            s0 = ror(w[i-15],7,32) ^ ror(w[i-15],18,32) ^ (w[i-15] >> 3)
            s1 = ror(w[i-2],17,32) ^ ror(w[i-2],19,32) ^ (w[i-2] >> 10)
            w[i] = (w[i-16] + s0 + w[i-7] + s1) % MOD32
        # Инициализация вспомогательных переменных:
        a = h0
        b = h1
        c = h2
        d = h3
        e = h4
        f = h5
        g = h6
        h = h7
        # Основной цикл:
        for i in range(64):
            S0 = ror(a,2,32) ^ ror(a,13,32) ^ ror(a,22,32)
            S1 = ror(e,6,32) ^ ror(e,11,32) ^ ror(e,25,32)
            Ch = (e & f) ^ ((~e) & g)
            Ma = (a & b) ^ (a & c) ^ (b & c)
            t1 = (h + S1 + Ch + k[i] + w[i]) % MOD32
            t2 = (S0 + Ma) % MOD32
            h = g
            g = f
            f = e
            e = (d + t1) % MOD32
            d = c
            c = b
            b = a
            a = (t1 + t2) % MOD32
        # Добавить полученные значения к ранее вычисленному результату:
        h0 = (h0 + a) % MOD32
        h1 = (h1 + b) % MOD32
        h2 = (h2 + c) % MOD32
        h3 = (h3 + d) % MOD32
        h4 = (h4 + e) % MOD32
        h5 = (h5 + f) % MOD32
        h6 = (h6 + g) % MOD32
        h7 = (h7 + h) % MOD32

    return struct.pack('>LLLLLLLL', h0, h1, h2, h3, h4, h5, h6, h7)


if __name__ == '__main__':
    # from profiler import Profiler
    # message = b'a' * 1024**2  # 1 MegaByte message
    # with Profiler() as p:
    #     print(codecs.encode(sha256_sum(message), 'hex').decode())
    # with Profiler() as p:
    #     print(hashlib.sha256(message).hexdigest())

    message = b'SHA-256 is one of the successor hash functions to SHA-1, and is one of the strongest hash functions available.'
    print(codecs.encode(sha256_sum(message), 'hex').decode())
    print(hashlib.sha256(message).hexdigest())

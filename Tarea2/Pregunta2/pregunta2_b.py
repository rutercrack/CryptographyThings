# Fuentes de extracción de codigo para SHA256: 

# https://github.com/keanemind/python-sha-256/tree/master
# https://github.com/oconnor663/sha256_project


def alg(bytes) -> bytes:
    """
    Para poder resolver esto tenemos que hacer un A(x) = x || padding(x) || m'
    Puesto que necesitamos hacer una especie de lenght extension attack para resolver el problema.
    El padding es el hecho por sha256.
    """
    padding = padding_bytes(len(bytes))

    return bytes + padding + b"sneakyattacker"


def adv(z: bytes, y: bytes) -> bool:
    
    """
    A partir de z = h_n(x), sabemos que esto es simplemente "el paso final" de h_n(x) y por tanto
    podemos usar z como un paso "intermedio" de una palabra que está procesando x||padding||m'. 
    En otras palabras, z implicaría el paso justo antes de comenzar a tomar m', y luego, por su puesto,
    el padding asociado a m'. En este caso, mi m' es "sneakyattacker".

    A partir de lo anterior, debemos seguir resolviendo el sha256 desde el paso especifico
    y simplemente alimentarle a "compress" z e m'(ojo que el algoritmo debe hacer el padding de m').
    Esto nos dará como resultado el sha256 de la palabra x||padding(x)||m', o en terminos de lo que queremos:
    h_n(A(x)). 
    """
    output = 0
    # Nota extra: el atacante conoce el largo de x pues es el parametro del juego.
    # Como sabemos que el largo de x = 32 bytes (pues n en SHA256 son 256 bits, es decir, 32 bytes)
    # Entonces segun enunciado el x de tamaño n es de tamaño 32 bytes.
    # Luego calculamos el largo de toda la concatenacion, para despues ver su padding asociado.
    new_len = 32 + len(padding_bytes(32)) + len(b"sneakyattacker")
    new_padding = padding_bytes(new_len)
    # Los nuevos bloques son el mensaje y el padding separados en bloques de 64 bytes.
    new_blocks = b"sneakyattacker" + new_padding
    state_words = [int.from_bytes(z[4 * i : 4 * i + 4], "big") for i in range(8)]
    i = 0
    while i < len(new_blocks):
        block = new_blocks[i : i + 64]
        # Partimos desde el z, y avanzamos por los nuevos bloques
        state_words = compress_block(state_words, block)
        i += 64
    output =  b"".join(x.to_bytes(4, "big") for x in state_words)

    if output == y:
        return True
    return False

####################################################################################################################################
####################################################################################################################################
############################### ELEMENTOS DE SHA256 NECESARIOS PARA ESTA IMPLEMENTACION ############################################
####################################################################################################################################
####################################################################################################################################

# fmt: off
IV = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

ROUND_CONSTANTS = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]
# fmt: on


### Building Blocks


def add32(*args):
    return sum(args) % (2**32)


def rightrotate32(x, n):
    assert x < 2**32, "x is too large. Did you use + instead of add32 somewhere?"
    right_part = x >> n
    left_part = x << (32 - n)
    return add32(left_part, right_part)


### The Message Schedule


def little_sigma0(word):
    return rightrotate32(word, 7) ^ rightrotate32(word, 18) ^ (word >> 3)


def little_sigma1(word):
    return rightrotate32(word, 17) ^ rightrotate32(word, 19) ^ (word >> 10)


def message_schedule_array(block):
    assert len(block) == 64
    w = []
    for i in range(16):
        assert i == len(w)
        w.append(int.from_bytes(block[4 * i : 4 * i + 4], "big"))
    for i in range(16, 64):
        s0 = little_sigma0(w[i - 15])
        s1 = little_sigma1(w[i - 2])
        w.append(add32(w[i - 16], s0, w[i - 7], s1))
    return w


### The Round Function


def big_sigma0(word):
    return rightrotate32(word, 2) ^ rightrotate32(word, 13) ^ rightrotate32(word, 22)


def big_sigma1(word):
    return rightrotate32(word, 6) ^ rightrotate32(word, 11) ^ rightrotate32(word, 25)


def choice(x, y, z):
    return (x & y) ^ (~x & z)


def majority(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)


def round(state, round_constant, schedule_word):
    S1 = big_sigma1(state[4])
    ch = choice(state[4], state[5], state[6])
    temp1 = add32(state[7], S1, ch, round_constant, schedule_word)
    S0 = big_sigma0(state[0])
    maj = majority(state[0], state[1], state[2])
    temp2 = add32(S0, maj)
    return [
        add32(temp1, temp2),
        state[0],
        state[1],
        state[2],
        add32(state[3], temp1),
        state[4],
        state[5],
        state[6],
    ]


### The Compression Function


def compress_block(input_state_words, block):
    w = message_schedule_array(block)
    state_words = input_state_words
    for round_number in range(64):
        round_constant = ROUND_CONSTANTS[round_number]
        schedule_word = w[round_number]
        state_words = round(state_words, round_constant, schedule_word)
    return [add32(x, y) for x, y in zip(input_state_words, state_words)]


### Padding


def padding_bytes(input_len):
    remainder_bytes = (input_len + 8) % 64
    filler_bytes = 64 - remainder_bytes
    zero_bytes = filler_bytes - 1
    encoded_bit_length = (8 * input_len).to_bytes(8, "big")
    return b"\x80" + b"\0" * zero_bytes + encoded_bit_length


### The Hash Function


def sha256(message):
    padded = message + padding_bytes(len(message))
    assert len(padded) % 64 == 0
    state_words = IV
    i = 0
    while i < len(padded):
        block = padded[i : i + 64]
        state_words = compress_block(state_words, block)
        i += 64
    return b"".join(x.to_bytes(4, "big") for x in state_words)

######################################################################
############################# MINI TEST ##############################
######################################################################

# import hashlib
# import os
# x = "hello mundito bonito aasdasdasda"
# x_bytes = x.encode()  # convierte string a bytes
# value = hashlib.sha256(x_bytes).digest()

# value2 = hashlib.sha256(alg(x_bytes)).digest()

# def random_32bytes():
#     return os.urandom(32)


# # Resultados
# print(adv(value, value2))
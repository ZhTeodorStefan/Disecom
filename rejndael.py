# ---------------Utils---------------

def print_hex(thing: list[int], name="thing"):
    print(f"{name}: ", end="")
    for number in thing:
        print(hex(number), end=", ")
    print()


def print_hex2(thing: list[int], name="thing"):
    """Prints a 16-byte state in AES column-major order."""
    print(f"{name}:")
    for row in range(4):
        for col in range(4):
            print(f"{hex(thing[col * 4 + row])}".rjust(6), end=" ")
        print()  # Newline after each row
    print()


def x_times(byte: int) -> int:
    return ((byte << 1) ^ 0x1b if byte & 0x80 else byte << 1) & 0xff


def mul_2(byte: int) -> int:
    """Multiply a number with 2 in Galois Field"""
    return x_times(byte)


def mul_3(byte: int) -> int:
    """Multiply a number with 3 in Galois Field"""
    return byte ^ x_times(byte)


def mul_4(byte: int) -> int:
    """Multiply a number with 4 in Galois Field"""
    return x_times(x_times(byte))


def mul_8(byte: int) -> int:
    """Multiply a number with 8 in Galois Field"""
    return x_times(x_times(x_times(byte)))


def mul_9(byte: int) -> int:
    """Multiply a number with 9 in Galois Field"""
    return byte ^ mul_8(byte)


def mul_B(byte: int) -> int:
    """Multiply a number with B in Galois Field"""
    return mul_8(byte) ^ mul_2(byte) ^ byte


def mul_D(byte: int) -> int:
    """Multiply a number with D in Galois Field"""
    return mul_8(byte) ^ mul_4(byte) ^ byte


def mul_E(byte: int) -> int:
    """Multiply a number with E in Galois Field"""
    return mul_8(byte) ^ mul_4(byte) ^ mul_2(byte)


# ---------------Input---------------

def input_splitter(text: str) -> list[bytearray]:
    """
    Converts text to bytes \n
    Splits into 16-byte blocks \n
    Pad the last block using PKCS#7 if necessary
    """
    # convert text to bytes
    byte_data = bytearray(text.encode())

    # add padding
    padding = 16 - len(text) % 16
    byte_data += bytearray([padding] * padding)

    # split into states
    # states = [byte_data[i:i+16] for i in range(0, len(byte_data), 16)]
    states = [bytearray(16) for _ in range(len(byte_data) // 16)]

    for i in range(len(byte_data)):
        block_index = i // 16
        row = i % 4
        col = (i // 4) % 4
        states[block_index][row * 4 + col] = byte_data[i]

    return states


def key_expansion(key: list[int], Nr: int, Nk: int) -> list[list[int]]:
    """
    Creates multiple round keys from the main key
    """
    round_keys = [key[4*i:4*i + 4] for i in range(Nk)]

    # print(round_keys)

    for i in range(Nk, 4 * (Nr + 1)):
        # print(f"round {i}")
        temp = round_keys[i-1][:]
        # print_hex(temp)

        if i % Nk == 0:
            # rotate to left
            temp.append(temp.pop(0))
            # print_hex(temp, "after rotation")

            # substitute each byte
            temp = [SBOX[byte] for byte in temp]
            # print_hex(temp, "after subbyte")

            # xor with rcon
            temp[0] ^= RCON[i//Nk - 1]
            # print_hex(temp, "alter rcon")

        elif Nk > 6 and i % Nk == 4:
            temp = [SBOX[byte] for byte in temp]

        # print_hex(round_keys[i - Nk], "w[i − Nk]")
        round_keys.append([round_keys[i - Nk][j] ^ temp[j] for j in range(4)])

        # print_hex(round_keys[-1], "round key")

    return round_keys


# ---------------Transformations---------------

def sub_bytes(state: bytearray):
    """Applies a substitution table (S-box) to each byte"""

    for i in range(len(state)):
        state[i] = SBOX[state[i]]


def inv_sub_bytes(state: bytearray):
    """Applies the inverse substitution table (Inv-S-box) to each byte"""

    for i in range(len(state)):
        state[i] = INV_SBOX[state[i]]


def shift_rows(state: bytearray):
    """Shifts each byte by its row index value"""

    for row_index in range(0, len(state), 4):
        row = state[row_index:row_index + 4]

        for _ in range(row_index // 4):
            row.append(row.pop(0))

        state[row_index:row_index + 4] = row


def inv_shift_rows(state: bytearray):
    """Shifts each byte by its row index value in the opposite direction"""

    for row_index in range(0, len(state), 4):
        row = state[row_index:row_index + 4]

        for _ in range(row_index // 4):
            row.insert(0, row.pop())

        state[row_index:row_index + 4] = row


def mix_columns(state: bytearray):
    """Multiply each column with a fixed matrix"""
    for i in range(4):
        a = state[i]
        b = state[i + 4]
        c = state[i + 8]
        d = state[i + 12]

        state[i] = mul_2(a) ^ mul_3(b) ^ c ^ d
        state[i + 4] = mul_2(b) ^ mul_3(c) ^ d ^ a
        state[i + 8] = mul_2(c) ^ mul_3(d) ^ a ^ b
        state[i + 12] = mul_2(d) ^ mul_3(a) ^ b ^ c


def inv_mix_columns(state: bytearray):
    """Multiply each column with the inverse fixed matrix"""
    for i in range(4):
        a = state[i]
        b = state[i + 4]
        c = state[i + 8]
        d = state[i + 12]

        state[i] = mul_E(a) ^ mul_B(b) ^ mul_D(c) ^ mul_9(d)
        state[i + 4] = mul_9(a) ^ mul_E(b) ^ mul_B(c) ^ mul_D(d)
        state[i + 8] = mul_D(a) ^ mul_9(b) ^ mul_E(c) ^ mul_B(d)
        state[i + 12] = mul_B(a) ^ mul_D(b) ^ mul_9(c) ^ mul_E(d)


def add_round_key(state: bytearray, round_key: list[list[int]]):    # 4 words (columns)
    """Adds a round key to the state matrix\n
    Round keys are previously generated from the main key"""

    for i in range(4):
        state[i] ^= round_key[i][0]
        state[i + 4] ^= round_key[i][1]
        state[i + 8] ^= round_key[i][2]
        state[i + 12] ^= round_key[i][3]


# ---------------AES---------------

def cypher(state: bytearray, Nr: int, round_keys: list[list[int]]):
    """Encrypts a state matrix of the initial text"""
    # print_hex(state, "Initial state")

    add_round_key(state, round_keys[:4])
    # print_hex(state, "First add round key")

    for round in range(1, Nr):
        sub_bytes(state)
        # print_hex(state, f"After {round} sub bytes")

        shift_rows(state)
        # print_hex(state, f"After {round} shift rows")

        mix_columns(state)
        # print_hex(state, f"After {round} mix columns")

        add_round_key(state, round_keys[4*round:4*(round+1)])
        # print_hex(state, f"After {round} add round key")

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, round_keys[4*Nr:4*(Nr+1)])


def inv_cypher(state: bytearray, Nr: int, round_keys: list[list[int]]):
    """Decrypts a state matrix of the encrypted text"""

    add_round_key(state, round_keys[-4:])

    for round in range(Nr-1, 0, -1):
        inv_shift_rows(state)

        inv_sub_bytes(state)

        add_round_key(state, round_keys[4*round:4*(round+1)])

        inv_mix_columns(state)

    inv_shift_rows(state)
    inv_sub_bytes(state)
    add_round_key(state, round_keys[:4])


def aes(text: str | bytearray, cypher_type: str, key: list[int], decrypt=False) -> str | bytearray:
    """Encrypts and decrypts text using AES (128, 192, or 256)"""

    if not decrypt and not isinstance(text, str):
        raise ValueError("Text type must be 'str' when encrypting")

    if decrypt:
        if not isinstance(text, bytearray):
            raise ValueError("Text type must be 'bytearray' when decrypting")

        if len(text) % 16 != 0:
            raise ValueError("Encrypted text must be a multiple of 16 bytes")

    if cypher_type not in aes_config:
        raise ValueError("cypher_type must be 'aes_128', 'aes_192', or 'aes_256'")

    key_size, Nr, Nk = aes_config[cypher_type]

    if len(key) != key_size:
        raise ValueError(f"Key must be {key_size} bytes, but got {len(key)} bytes")

    round_keys = key_expansion(key, Nr, Nk)

    if decrypt:
        decrypted_bytes = bytearray()

        for i in range(0, len(text), 16):
            state = text[i:i+16]
            inv_cypher(state, Nr, round_keys)

            column_major_state = bytearray(16)
            for col in range(4):
                for row in range(4):
                    column_major_state[col * 4 + row] = state[row * 4 + col]

            decrypted_bytes.extend(column_major_state)

        return decrypted_bytes[:-decrypted_bytes[-1]].decode("utf-8")

    else:
        encrypted_bytes = bytearray()
        for state in input_splitter(text):
            cypher(state, Nr, round_keys)

            # This is for displaying the encrypted text
            # column_major_state = bytearray(16)
            # for col in range(4):
            #     for row in range(4):
            #         column_major_state[col * 4 + row] = state[row * 4 + col]

            encrypted_bytes.extend(state)

        return encrypted_bytes


# ---------------Constants---------------

# key length
Nk = (4, 6, 8)      # in bits (128, 192, 256)

# block size (4 words, each 4 bytes)
Nb = 4              # in bits (128)

# number of rounds
Nr = (10, 12, 14)

aes_config = {
    "aes_128": (Nb*Nk[0], Nr[0], Nk[0]),
    "aes_192": (Nb*Nk[1], Nr[1], Nk[1]),
    "aes_256": (Nb*Nk[2], Nr[2], Nk[2]),
}

RCON = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D
)

SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

INV_SBOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

TEST_KEYS = {
    "aes_128": [
        [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c],
    ],
    "aes_192": [
        [0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8, 0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8,
         0xea, 0xd2, 0x52, 0x2c, 0x6b, 0x7b],
    ],
    "aes_256": [
        [0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35,
         0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4],
    ]
}


if __name__ == "__main__":
    encrypted_text = aes("Lingan guli guli guliii wacha linganguu linganguu", "aes_128", TEST_KEYS["aes_128"][0])

    print(encrypted_text)

    decrypted_text = aes(encrypted_text, "aes_128", TEST_KEYS["aes_128"][0], decrypt=True)

    print(decrypted_text)

    encrypted_text = aes("Lingan guli guli guliii wacha linganguu linganguu", "aes_192",
                         TEST_KEYS["aes_192"][0])

    print(encrypted_text)

    decrypted_text = aes(encrypted_text, "aes_192",
                         TEST_KEYS["aes_192"][0], decrypt=True)

    print(decrypted_text)

    encrypted_text = aes("Lingan guli guli guliii wacha linganguu linganguu", "aes_256",
                         TEST_KEYS["aes_256"][0])

    print(encrypted_text)

    decrypted_text = aes(encrypted_text, "aes_256",
                         TEST_KEYS["aes_256"][0], decrypt=True)

    print(decrypted_text)

    # state = bytearray([0x32, 0x88, 0x31, 0xe0,
    #                    0x43, 0x5a, 0x31, 0x37,
    #                    0xf6, 0x30, 0x98, 0x07,
    #                    0xa8, 0x8d, 0xa2, 0x34])

    # states = input_splitter("Ana are mere moi si mari")
    #
    # round_keys = key_expansion([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c], Nr[0], Nk[0])
    #
    # for state in states:
    #     print_hex(state, "Before enc")
    #
    #     cypher(state, Nr[0], round_keys)
    #
    #     print_hex(state, "After enc")
    #
    # for state in states:
    #     print_hex(state, "Before dec")
    #
    #     inv_cypher(state, Nr[0], round_keys)
    #
    #     print_hex(state, "After dec")
    #
    #     column_major_state = state
    #     state = bytearray(16)
    #
    #     for col in range(4):
    #         for row in range(4):
    #             state[row * 4 + col] = column_major_state[col * 4 + row]
    #
    #     print(state)

    # for state in input_splitter("Ana are mere moi"):
    #     print_hex(state, "Before")
    #
    #     cypher(state, Nr[0], round_keys)
    #
    #     print_hex(state, "After")

    # mix_columns(state)
    #
    # print(state)

    # Test sub bytes and shift rows
    # states = input_splitter("Ana are mere multe si frumoase s")
    # print(states)
    #
    # for i in range(len(states)):
    #     sub_bytes(states[i])
    # print(states[:])
    #
    # for i in range(len(states)):
    #     shift_rows(states[i])
    # print(states[:])

    # Test key expansion
    # print([[hex(x) for x in key] for key in key_expansion([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab,
    #                                                        0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c], Nr[0], Nk[0])])
    #
    # print([[hex(x) for x in key] for key in key_expansion([0x8e, 0x73, 0xb0, 0xf7, 0xda, 0x0e, 0x64, 0x52, 0xc8,
    #                                                        0x10, 0xf3, 0x2b, 0x80, 0x90, 0x79, 0xe5, 0x62, 0xf8, 0xea,
    #                                                        0xd2, 0x52, 0x2c, 0x6b, 0x7b], Nr[1], Nk[1])])
    #
    # print([[hex(x) for x in key] for key in key_expansion([0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 0x2b,
    #                                                        0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81, 0x1f, 0x35, 0x2c,
    #                                                        0x07, 0x3b, 0x61, 0x08, 0xd7, 0x2d, 0x98, 0x10, 0xa3, 0x09,
    #                                                        0x14, 0xdf, 0xf4], Nr[2], Nk[2])])

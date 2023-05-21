import random

# aes_sbox
S_Box = [
    [int('63', 16), int('7c', 16), int('77', 16), int('7b', 16), int('f2', 16), int('6b', 16), int('6f', 16), int('c5', 16), int(
        '30', 16), int('01', 16), int('67', 16), int('2b', 16), int('fe', 16), int('d7', 16), int('ab', 16), int('76', 16)],
    [int('ca', 16), int('82', 16), int('c9', 16), int('7d', 16), int('fa', 16), int('59', 16), int('47', 16), int('f0', 16), int(
        'ad', 16), int('d4', 16), int('a2', 16), int('af', 16), int('9c', 16), int('a4', 16), int('72', 16), int('c0', 16)],
    [int('b7', 16), int('fd', 16), int('93', 16), int('26', 16), int('36', 16), int('3f', 16), int('f7', 16), int('cc', 16), int(
        '34', 16), int('a5', 16), int('e5', 16), int('f1', 16), int('71', 16), int('d8', 16), int('31', 16), int('15', 16)],
    [int('04', 16), int('c7', 16), int('23', 16), int('c3', 16), int('18', 16), int('96', 16), int('05', 16), int('9a', 16), int(
        '07', 16), int('12', 16), int('80', 16), int('e2', 16), int('eb', 16), int('27', 16), int('b2', 16), int('75', 16)],
    [int('09', 16), int('83', 16), int('2c', 16), int('1a', 16), int('1b', 16), int('6e', 16), int('5a', 16), int('a0', 16), int(
        '52', 16), int('3b', 16), int('d6', 16), int('b3', 16), int('29', 16), int('e3', 16), int('2f', 16), int('84', 16)],
    [int('53', 16), int('d1', 16), int('00', 16), int('ed', 16), int('20', 16), int('fc', 16), int('b1', 16), int('5b', 16), int(
        '6a', 16), int('cb', 16), int('be', 16), int('39', 16), int('4a', 16), int('4c', 16), int('58', 16), int('cf', 16)],
    [int('d0', 16), int('ef', 16), int('aa', 16), int('fb', 16), int('43', 16), int('4d', 16), int('33', 16), int('85', 16), int(
        '45', 16), int('f9', 16), int('02', 16), int('7f', 16), int('50', 16), int('3c', 16), int('9f', 16), int('a8', 16)],
    [int('51', 16), int('a3', 16), int('40', 16), int('8f', 16), int('92', 16), int('9d', 16), int('38', 16), int('f5', 16), int(
        'bc', 16), int('b6', 16), int('da', 16), int('21', 16), int('10', 16), int('ff', 16), int('f3', 16), int('d2', 16)],
    [int('cd', 16), int('0c', 16), int('13', 16), int('ec', 16), int('5f', 16), int('97', 16), int('44', 16), int('17', 16), int(
        'c4', 16), int('a7', 16), int('7e', 16), int('3d', 16), int('64', 16), int('5d', 16), int('19', 16), int('73', 16)],
    [int('60', 16), int('81', 16), int('4f', 16), int('dc', 16), int('22', 16), int('2a', 16), int('90', 16), int('88', 16), int(
        '46', 16), int('ee', 16), int('b8', 16), int('14', 16), int('de', 16), int('5e', 16), int('0b', 16), int('db', 16)],
    [int('e0', 16), int('32', 16), int('3a', 16), int('0a', 16), int('49', 16), int('06', 16), int('24', 16), int('5c', 16), int(
        'c2', 16), int('d3', 16), int('ac', 16), int('62', 16), int('91', 16), int('95', 16), int('e4', 16), int('79', 16)],
    [int('e7', 16), int('c8', 16), int('37', 16), int('6d', 16), int('8d', 16), int('d5', 16), int('4e', 16), int('a9', 16), int(
        '6c', 16), int('56', 16), int('f4', 16), int('ea', 16), int('65', 16), int('7a', 16), int('ae', 16), int('08', 16)],
    [int('ba', 16), int('78', 16), int('25', 16), int('2e', 16), int('1c', 16), int('a6', 16), int('b4', 16), int('c6', 16), int(
        'e8', 16), int('dd', 16), int('74', 16), int('1f', 16), int('4b', 16), int('bd', 16), int('8b', 16), int('8a', 16)],
    [int('70', 16), int('3e', 16), int('b5', 16), int('66', 16), int('48', 16), int('03', 16), int('f6', 16), int('0e', 16), int(
        '61', 16), int('35', 16), int('57', 16), int('b9', 16), int('86', 16), int('c1', 16), int('1d', 16), int('9e', 16)],
    [int('e1', 16), int('f8', 16), int('98', 16), int('11', 16), int('69', 16), int('d9', 16), int('8e', 16), int('94', 16), int(
        '9b', 16), int('1e', 16), int('87', 16), int('e9', 16), int('ce', 16), int('55', 16), int('28', 16), int('df', 16)],
    [int('8c', 16), int('a1', 16), int('89', 16), int('0d', 16), int('bf', 16), int('e6', 16), int('42', 16), int('68', 16), int(
        '41', 16), int('99', 16), int('2d', 16), int('0f', 16), int('b0', 16), int('54', 16), int('bb', 16), int('16', 16)]
]

S_Box_Reversed = [
    [int('52', 16), int('09', 16), int('6a', 16), int('d5', 16), int('30', 16), int('36', 16), int('a5', 16), int('38', 16), int(
        'bf', 16), int('40', 16), int('a3', 16), int('9e', 16), int('81', 16), int('f3', 16), int('d7', 16), int('fb', 16)],
    [int('7c', 16), int('e3', 16), int('39', 16), int('82', 16), int('9b', 16), int('2f', 16), int('ff', 16), int('87', 16), int(
        '34', 16), int('8e', 16), int('43', 16), int('44', 16), int('c4', 16), int('de', 16), int('e9', 16), int('cb', 16)],
    [int('54', 16), int('7b', 16), int('94', 16), int('32', 16), int('a6', 16), int('c2', 16), int('23', 16), int('3d', 16), int(
        'ee', 16), int('4c', 16), int('95', 16), int('0b', 16), int('42', 16), int('fa', 16), int('c3', 16), int('4e', 16)],
    [int('08', 16), int('2e', 16), int('a1', 16), int('66', 16), int('28', 16), int('d9', 16), int('24', 16), int('b2', 16), int(
        '76', 16), int('5b', 16), int('a2', 16), int('49', 16), int('6d', 16), int('8b', 16), int('d1', 16), int('25', 16)],
    [int('72', 16), int('f8', 16), int('f6', 16), int('64', 16), int('86', 16), int('68', 16), int('98', 16), int('16', 16), int(
        'd4', 16), int('a4', 16), int('5c', 16), int('cc', 16), int('5d', 16), int('65', 16), int('b6', 16), int('92', 16)],
    [int('6c', 16), int('70', 16), int('48', 16), int('50', 16), int('fd', 16), int('ed', 16), int('b9', 16), int('da', 16), int(
        '5e', 16), int('15', 16), int('46', 16), int('57', 16), int('a7', 16), int('8d', 16), int('9d', 16), int('84', 16)],
    [int('90', 16), int('d8', 16), int('ab', 16), int('00', 16), int('8c', 16), int('bc', 16), int('d3', 16), int('0a', 16), int(
        'f7', 16), int('e4', 16), int('58', 16), int('05', 16), int('b8', 16), int('b3', 16), int('45', 16), int('06', 16)],
    [int('d0', 16), int('2c', 16), int('1e', 16), int('8f', 16), int('ca', 16), int('3f', 16), int('0f', 16), int('02', 16), int(
        'c1', 16), int('af', 16), int('bd', 16), int('03', 16), int('01', 16), int('13', 16), int('8a', 16), int('6b', 16)],
    [int('3a', 16), int('91', 16), int('11', 16), int('41', 16), int('4f', 16), int('67', 16), int('dc', 16), int('ea', 16), int(
        '97', 16), int('f2', 16), int('cf', 16), int('ce', 16), int('f0', 16), int('b4', 16), int('e6', 16), int('73', 16)],
    [int('96', 16), int('ac', 16), int('74', 16), int('22', 16), int('e7', 16), int('ad', 16), int('35', 16), int('85', 16), int(
        'e2', 16), int('f9', 16), int('37', 16), int('e8', 16), int('1c', 16), int('75', 16), int('df', 16), int('6e', 16)],
    [int('47', 16), int('f1', 16), int('1a', 16), int('71', 16), int('1d', 16), int('29', 16), int('c5', 16), int('89', 16), int(
        '6f', 16), int('b7', 16), int('62', 16), int('0e', 16), int('aa', 16), int('18', 16), int('be', 16), int('1b', 16)],
    [int('fc', 16), int('56', 16), int('3e', 16), int('4b', 16), int('c6', 16), int('d2', 16), int('79', 16), int('20', 16), int(
        '9a', 16), int('db', 16), int('c0', 16), int('fe', 16), int('78', 16), int('cd', 16), int('5a', 16), int('f4', 16)],
    [int('1f', 16), int('dd', 16), int('a8', 16), int('33', 16), int('88', 16), int('07', 16), int('c7', 16), int('31', 16), int(
        'b1', 16), int('12', 16), int('10', 16), int('59', 16), int('27', 16), int('80', 16), int('ec', 16), int('5f', 16)],
    [int('60', 16), int('51', 16), int('7f', 16), int('a9', 16), int('19', 16), int('b5', 16), int('4a', 16), int('0d', 16), int(
        '2d', 16), int('e5', 16), int('7a', 16), int('9f', 16), int('93', 16), int('c9', 16), int('9c', 16), int('ef', 16)],
    [int('a0', 16), int('e0', 16), int('3b', 16), int('4d', 16), int('ae', 16), int('2a', 16), int('f5', 16), int('b0', 16), int(
        'c8', 16), int('eb', 16), int('bb', 16), int('3c', 16), int('83', 16), int('53', 16), int('99', 16), int('61', 16)],
    [int('17', 16), int('2b', 16), int('04', 16), int('7e', 16), int('ba', 16), int('77', 16), int('d6', 16), int('26', 16), int(
        'e1', 16), int('69', 16), int('14', 16), int('63', 16), int('55', 16), int('21', 16), int('0c', 16), int('7d', 16)]
]


def substitute_byte(input_byte):
    """
    Face lookup în tabelul AES S-Box folosind primele 4 biți și ultimii 4 biți ai byte-ului ca indici.
    """
    # Shiftăm bitii byte-ului la dreapta cu 4 poziții pentru a obține primele 4 biți.
    # Aplicăm masca 15 (00001111 în binar) pentru a obține ultimii 4 biți.
    return S_Box[input_byte >> 4][input_byte & 15]


def substitute_byte_reversed(input_byte):
    """
    Face lookup în tabelul invers al AES S-Box folosind primele 4 biți și ultimii 4 biți ai byte-ului ca indici.
    """
    return S_Box_Reversed[input_byte >> 4][input_byte & 15]

def get_blocks_of_16_bytes(input_data : bytearray):
    """
    Împarte datele de intrare în blocuri de 16 bytes și aranjează fiecare bloc într-o matrice 4x4.
    Rezultatul este o listă de matrici.
    """
    blocks = []
    for i in range(len(input_data)//16):
        block_bytes = input_data[i*16: i*16 + 16]
        block_matrix = [[block_bytes[i + j*4] for j in range(4)] for i in range(4)]
        blocks.append(block_matrix)
    return blocks

def rotire_la_stanga_cu_n(list, shift_count=1):
    """
    Rotește elementele unei liste la stânga cu un număr dat de poziții.
    """
    return list[shift_count:] + list[:shift_count]

def generate_round_constants(total_rounds):
    """
    Generează constantele de rundă pentru algoritmul AES.
    """
    round_constants = [[1, 0, 0, 0]]
    for _ in range(1, total_rounds):
        new_constant = [round_constants[-1][0]*2, 0, 0, 0]
        if new_constant[0] > 0x80:
            new_constant[0] ^= 0x11b
        round_constants.append(new_constant)
    return round_constants

def expand_key(key: bytearray, total_rounds: int):
    """
    Extinde cheia inițială prin aplicarea operațiilor de rotire, substituire și xor pentru fiecare rundă.
    """
    round_constants = generate_round_constants(total_rounds)

    # Convertește cheia într-o matrice 4x4
    key_matrix = get_blocks_of_16_bytes(key)[0]

    for round in range(total_rounds):
        # Preia ultima coloană din matricea cheii
        last_column = [row[-1] for row in key_matrix]
        
        # Rotire la stânga
        rotated_column = rotire_la_stanga_cu_n(last_column)
        
        # Substituie byte cu valori din S-Box
        substituted_column = [substitute_byte(byte) for byte in rotated_column]
        
        # Aplică constanta de rundă printr-un xor
        round_const_applied = [substituted_column[i] ^ round_constants[round][i] for i in range(len(rotated_column))]

        # Rezultatul este xorat cu byte-ul în aceeași poziție din cheia rundei precedente, se adaugă o nouă coloană
        for row in range(4):
            key_matrix[row] += bytes([round_const_applied[row] ^ key_matrix[row][round*4]])

        # Se procesează ultimele 3 coloane
        for row_index in range(len(key_matrix)):
            for col_index in range(1, 4):
                key_matrix[row_index] += bytes([key_matrix[row_index][round*4+col_index] ^ key_matrix[row_index][round*4+col_index+3]])

    return key_matrix


def add_round_key(block_matrix, key_matrix):
    """
    Realizează un xor între matricea blocului de date și matricea cheii rundei.
    """
    result = []
    for row in range(4):
        result.append([])
        for col in range(4):
            # Se adaugă la sfârșitul ultimului element din 'result'
            result[-1].append(block_matrix[row][col] ^ key_matrix[row][col])
    return result

def get_right_key_for_round(expanded_key, round):
    """
    Această funcție ia cheia extinsă și numărul rundei, returnând cheia corespunzătoare rundei.
    """
    return [row[round*4: round*4 + 4] for row in expanded_key]

def multiply2(value):
    """
    Multiplică valoarea dată cu 2, în cadrul corpului Galois. Folosit în operația de amestecare a coloanelor.
    """
    shifted_value = value << 1
    shifted_value &= 0xff
    if (value & 128) != 0:
        shifted_value ^= 0x1b
    return shifted_value

def multiply3(value):
    """
    Multiplică valoarea dată cu 3, în cadrul corpului Galois. Folosit în operația de amestecare a coloanelor.
    """
    return multiply2(value) ^ value

def mix_columns(grid):
    """
    Aplică operația MixColumns pe matricea dată (grid).
    MixColumns este o transformare care operează pe fiecare coloană a datelor, combinându-le.
    """
    new_grid = [[], [], [], []]
    for i in range(4):
        column = [grid[j][i] for j in range(4)]  # extrage coloana
        mixed_column = mix_column(column)
        for i in range(4):
            new_grid[i].append(mixed_column[i])  # adăugăm coloanele mixate înapoi în grilă
    return new_grid

def mix_column(column):
    """
    Aplică operația MixColumn pe o singură coloană.
    """
    return [
        multiply2(column[0]) ^ multiply3(column[1]) ^ column[2] ^ column[3],
        column[0] ^ multiply2(column[1]) ^ multiply3(column[2]) ^ column[3],
        column[0] ^ column[1] ^ multiply2(column[2]) ^ multiply3(column[3]),
        multiply3(column[0]) ^ column[1] ^ column[2] ^ multiply2(column[3]),
    ]

def encryption(key, plaintext):
    # Se adaugă padding (umplere) cu byte-ul \x00 până la lungimea de 16 bytes.
    padding = bytes(16 - len(plaintext) % 16)
    if len(padding) != 16:
        plaintext += padding

    # Se împarte plaintextul în blocuri de 16 bytes.
    plaintext_blocks = get_blocks_of_16_bytes(plaintext)

    # Se generează cheia extinsă pentru toate runda.
    expanded_key = expand_key(key, 11)

    # Se adaugă cheia rundei inițiale la blocurile de plaintext.
    blocks_with_initial_round_key = []
    initial_round_key = get_right_key_for_round(expanded_key, 0)

    for block in plaintext_blocks:
        blocks_with_initial_round_key.append(add_round_key(block, initial_round_key))

    # Se parcurg cele 9 runde ale criptării AES.
    for round_number in range(1, 10):
        round_blocks = []
        for block in blocks_with_initial_round_key:
            # Se aplică SubBytes, ShiftRows și MixColumns.
            substituted_block = [[substitute_byte(byte) for byte in row] for row in block]
            shifted_block = [rotire_la_stanga_cu_n(substituted_block[i], i) for i in range(4)]
            mixed_block = mix_columns(shifted_block)
            # Se adaugă cheia rundei.
            round_key = get_right_key_for_round(expanded_key, round_number)
            round_block = add_round_key(mixed_block, round_key)
            round_blocks.append(round_block)
        blocks_with_initial_round_key = round_blocks

    # Se efectuează runda finală (fără MixColumns).
    final_round_blocks = []
    final_round_key = get_right_key_for_round(expanded_key, 10)
    for block in blocks_with_initial_round_key:
        # Se aplică SubBytes și ShiftRows.
        substituted_block = [[substitute_byte(byte) for byte in row] for row in block]
        shifted_block = [rotire_la_stanga_cu_n(substituted_block[i], i) for i in range(4)]
        # Se adaugă cheia rundei finale.
        final_round_block = add_round_key(shifted_block, final_round_key)
        final_round_blocks.append(final_round_block)

    # Se transformă blocurile finale în bytes și se returnează rezultatul.
    ciphertext = [block[row][column] for block in final_round_blocks for column in range(4) for row in range(4)]
    
    return bytes(ciphertext)

def decryption(key, ciphertext):
    # Se împarte textul criptat în blocuri de 16 bytes.
    ciphertext_blocks = get_blocks_of_16_bytes(ciphertext)
    # Se generează cheia extinsă pentru toate runda.
    expanded_key = expand_key(key, 11)
    # Se extrage cheia pentru ultima rundă.
    final_round_key = get_right_key_for_round(expanded_key, 10)

    # Se efectuează inversul rundei finale (fără InverseMixColumns).
    initial_round_blocks = []
    for block in ciphertext_blocks:
        # Se elimină cheia rundei finale.
        final_round_block = add_round_key(block, final_round_key)
        # Se aplică InverseShiftRows și InverseSubBytes.
        inv_shifted_block = [rotire_la_stanga_cu_n(final_round_block[i], -1 * i) for i in range(4)]
        inv_substituted_block = [[substitute_byte_reversed(byte) for byte in row] for row in inv_shifted_block]
        initial_round_blocks.append(inv_substituted_block)

    # Se parcurg cele 9 runde inverse ale decriptării AES.
    for round_number in range(9, 0, -1):
        round_blocks = []
        for block in initial_round_blocks:
            # Se extrage cheia corespunzătoare rundei.
            round_key = get_right_key_for_round(expanded_key, round_number)
            # Se elimină cheia rundei.
            block_with_round_key_removed = add_round_key(block, round_key)
            # Se aplică InverseMixColumns de trei ori pentru a obține inversul operației.
            inv_mixed_block = mix_columns(block_with_round_key_removed)
            inv_mixed_block = mix_columns(inv_mixed_block)
            inv_mixed_block = mix_columns(inv_mixed_block)
            # Se aplică InverseShiftRows și InverseSubBytes.
            inv_shifted_block = [rotire_la_stanga_cu_n(inv_mixed_block[i], -1 * i) for i in range(4)]
            inv_substituted_block = [[substitute_byte_reversed(byte) for byte in row] for row in inv_shifted_block]
            round_blocks.append(inv_substituted_block)
        initial_round_blocks = round_blocks

    # Se elimină cheia inițială.
    plaintext_blocks = []
    initial_round_key = get_right_key_for_round(expanded_key, 0)
    for block in initial_round_blocks:
        plaintext_blocks.append(add_round_key(block, initial_round_key))

    # Se transformă blocurile finale în bytes și se returnează rezultatul.
    plaintext = [block[row][column] for block in plaintext_blocks for column in range(4) for row in range(4)]
    return bytes(plaintext)

def generate_key():
    # Inițializează un bytearray gol.
    generated_key = bytearray()
    # Generează 16 octeți aleatori.
    for _ in range(16):
        random_byte = random.randint(0, 255)
        generated_key.append(random_byte)
    return generated_key

# Generează o cheie
key_bytes = generate_key()

# Scrie cheia într-un fișier.
with open('key.txt', 'wb') as key_file:
    key_file.write(key_bytes)

# Criptează mesajul folosind cheia generată.
encrypted_message = encryption(key_bytes, b'a mote of dust suspended in a sunbeam')
print(encrypted_message)

# Citeste cheia din fișier.
with open('key.txt', 'rb') as key_file:
        read_key = key_file.read()

# Decriptează mesajul folosind cheia citită din fișier.
decrypted_message = decryption(read_key, encrypted_message)
print(decrypted_message)
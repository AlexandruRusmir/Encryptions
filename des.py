import random

# Functia hex2bin converteste un sir hexazecimal in sir binar.
def hex2bin(s):
    # Un dictionar care mapeaza fiecare cifra hexazecimala la echivalentul sau binar pe 4 biti.
    mp = {'0': "0000",
          '1': "0001",
          '2': "0010",
          '3': "0011",
          '4': "0100",
          '5': "0101",
          '6': "0110",
          '7': "0111",
          '8': "1000",
          '9': "1001",
          'A': "1010",
          'B': "1011",
          'C': "1100",
          'D': "1101",
          'E': "1110",
          'F': "1111"}
    bin = ""
    # Parcurge sirul hexazecimal si adauga echivalentul binar pentru fiecare caracter.
    for i in range(len(s)):
        bin = bin + mp[s[i]]
    return bin

# Functia bin2hex converteste un sir binar in sir hexazecimal.
def bin2hex(s):
    # Un dictionar care mapeaza fiecare grup de 4 biti la echivalentul sau hexazecimal.
    mp = {"0000": '0',
          "0001": '1',
          "0010": '2',
          "0011": '3',
          "0100": '4',
          "0101": '5',
          "0110": '6',
          "0111": '7',
          "1000": '8',
          "1001": '9',
          "1010": 'A',
          "1011": 'B',
          "1100": 'C',
          "1101": 'D',
          "1110": 'E',
          "1111": 'F'}
    hex = ""
    # Parcurge sirul binar, grupand bitii in grupuri de 4 si adaugand echivalentul hexazecimal pentru fiecare grup.
    for i in range(0, len(s), 4):
        ch = ""
        ch = ch + s[i]
        ch = ch + s[i + 1]
        ch = ch + s[i + 2]
        ch = ch + s[i + 3]
        hex = hex + mp[ch]
 
    return hex

# Functia bin2dec converteste un numar binar in numar zecimal.
def bin2dec(binary):
    decimal, i = 0, 0
    while(binary != 0):
        dec = binary % 10
        decimal = decimal + dec * pow(2, i)
        binary = binary//10
        i += 1
    return decimal

# Functia dec2bin converteste un numar zecimal in numar binar, rezultatul avand lungimea multiplu de 4.
def dec2bin(num):
    res = bin(num).replace("0b", "")
    if(len(res) % 4 != 0):
        div = len(res) / 4
        div = int(div)
        counter = (4 * (div + 1)) - len(res)
        for i in range(0, counter):
            res = '0' + res
    return res

# Functia permute rearanjeaza sirul k conform pozitiilor specificate in lista arr, cu lungimea n.
def permute(k, arr, n):
    permutation = ""
    for i in range(0, n):
        permutation = permutation + k[arr[i] - 1]
    return permutation

# Functia shift_left realizeaza o deplasare circulara la stanga cu nth_shifts pozitii a sirului k.
def shift_left(k, nth_shifts):
    s = ""
    for i in range(nth_shifts):
        for j in range(1, len(k)):
            s = s + k[j]
        s = s + k[0]
        k = s
        s = ""
    return k

# Functia xor calculeaza xor-ul a doua siruri de caractere binare a si b.
def xor(a, b):
    ans = ""
    for i in range(len(a)):
        if a[i] == b[i]:
            ans = ans + "0"
        else:
            ans = ans + "1"
    return ans

IP =[58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7]

E = [32, 1, 2, 3, 4, 5, 4, 5,
    6, 7, 8, 9, 8, 9, 10, 11,
    12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21,
    22, 23, 24, 25, 24, 25, 26, 27,
    28, 29, 28, 29, 30, 31, 32, 1]

P = [16, 7, 20, 21,
	29, 12, 28, 17,
	1, 15, 23, 26,
	5, 18, 31, 10,
	2, 8, 24, 14,
	32, 27, 3, 9,
	19, 13, 30, 6,
	22, 11, 4, 25]

S = [[[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
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
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

# Final Permutation Table
IP_1 = [40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41, 9, 49, 17, 57, 25]

def encrypt(pt, rkb, rk):
    pt = hex2bin(pt)

    # Permutare initiala
    pt = permute(pt, IP, 64)
    print("Dupa permutarea initiala", bin2hex(pt))

    # Impartirea textului in doua parti
    left = pt[0:32]
    right = pt[32:64]
    for i in range(0, 16):
        # Expandarea partii drepte de la 32 de biti la 48 de biti
        right_expanded = permute(right, E, 48)

        # XOR intre partea dreapta expandata si cheia rundei
        xor_x = xor(right_expanded, rkb[i])

        # Substitutie folosind S-boxurile
        sbox_str = ""
        for j in range(0, 8):
            row = bin2dec(int(xor_x[j * 6] + xor_x[j * 6 + 5]))
            col = bin2dec(int(xor_x[j * 6 + 1] + xor_x[j * 6 + 2] + xor_x[j * 6 + 3] + xor_x[j * 6 + 4]))
            val = S[j][row][col]
            sbox_str = sbox_str + dec2bin(val)

        # Permutare dupa substitutie
        sbox_str = permute(sbox_str, P, 32)

        # XOR intre partea stanga si rezultatul permutarii
        result = xor(left, sbox_str)
        left = result

        # Schimbare intre partile stanga si dreapta
        if(i != 15):
            left, right = right, left
        print("Iteratia ", i + 1, ": ", bin2hex(left), " ", bin2hex(right), " ", rk[i])

    # Combinarea partilor stanga si dreapta
    combine = left + right

    # Permutare finala pentru a obtine textul cifrat
    cipher_text = permute(combine, IP_1, 64)
    return bin2hex(cipher_text)

def generate_des_key():
    # Initializează un bytearray gol.
    key = bytearray()
    # Generează 8 octeți aleatori.
    for _ in range(8):
        byte = random.randint(0, 255)
        key.append(byte)
    # Transformă bytearray într-un șir hexazecimal.
    hex_key = ''.join(format(b, '02X') for b in key)
    return hex_key

# Generează o cheie
key = generate_des_key()
with open('DES_key.txt', 'w') as file:
    file.write(key)
key = hex2bin(key)

# --tabela pentru eliminarea bitilor de paritate
keyp = [57, 49, 41, 33, 25, 17, 9,
		1, 58, 50, 42, 34, 26, 18,
		10, 2, 59, 51, 43, 35, 27,
		19, 11, 3, 60, 52, 44, 36,
		63, 55, 47, 39, 31, 23, 15,
		7, 62, 54, 46, 38, 30, 22,
		14, 6, 61, 53, 45, 37, 29,
		21, 13, 5, 28, 20, 12, 4]

# obtinerea cheii de 56 de biti din cheia de 64 de biti folosind bitii de paritate
key = permute(key, keyp, 56)

# Numarul de deplasari pe biti
shift_table = [1, 1, 2, 2,
			2, 2, 2, 2,
			1, 2, 2, 2,
			2, 2, 2, 1]

# Tabela de compresie a cheii: compresia cheii de la 56 de biti la 48 de biti
key_comp = [14, 17, 11, 24, 1, 5,
			3, 28, 15, 6, 21, 10,
			23, 19, 12, 4, 26, 8,
			16, 7, 27, 20, 13, 2,
			41, 52, 31, 37, 47, 55,
			30, 40, 51, 45, 33, 48,
			44, 49, 39, 56, 34, 53,
			46, 42, 50, 36, 29, 32]

# Impartirea cheii in doua parti
left = key[0:28] # rkb pentru cheile rundei in binar
right = key[28:56] # rk pentru cheile rundei in hexazecimal

rkb = []
rk = []
for i in range(0, 16):
	# Deplasarea bitilor cu n pozitii verificand din tabela de deplasari
	left = shift_left(left, shift_table[i])
	right = shift_left(right, shift_table[i])

	# Combinarea partilor stanga si dreapta
	combine_str = left + right

	# Compresia cheii de la 56 la 48 de biti
	round_key = permute(combine_str, key_comp, 48)

	rkb.append(round_key)
	rk.append(bin2hex(round_key))

pt = "0123456789EFDCBF"
print("Criptare")
cipher_text = encrypt(pt, rkb, rk)

print("Text encriptat: ", cipher_text)

# Citirea cheii din fișier pentru decriptare
with open('DES_key.txt', 'r') as file:
    key = file.read()
key = hex2bin(key)

# obtinerea cheii de 56 de biti din cheia de 64 de biti folosind bitii de paritate
key = permute(key, keyp, 56)
# Impartirea cheii in doua parti
left = key[0:28] # rkb pentru cheile rundei in binar
right = key[28:56] # rk pentru cheile rundei in hexazecimal

rkb = []
rk = []
for i in range(0, 16):
	# Deplasarea bitilor cu n pozitii verificand din tabela de deplasari
	left = shift_left(left, shift_table[i])
	right = shift_left(right, shift_table[i])

	# Combinarea partilor stanga si dreapta
	combine_str = left + right

	# Compresia cheii de la 56 la 48 de biti
	round_key = permute(combine_str, key_comp, 48)

	rkb.append(round_key)
	rk.append(bin2hex(round_key))
print("Decriptare")
rkb_rev = rkb[::-1]
rk_rev = rk[::-1]
text = encrypt(cipher_text, rkb_rev, rk_rev)
print("Text decriptat: ", text)
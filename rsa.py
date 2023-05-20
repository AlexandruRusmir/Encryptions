import random
from math import gcd  # cel mai mare divizor comun

def este_prim(n):
    """
    Utilizează algoritmul Miller-Rabin pentru a verifica dacă un număr este prim.
    """
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True


def creeaza_numar_prim(lungime_biti):
    """
    Generează un număr aleatoriu cu o lungime de biți specificată, iar apoi îl verifică dacă este prim.
    Dacă numărul generat nu este prim, continuă generarea de numere până când găsește unul prim.
    """
    while True:
        n = random.getrandbits(lungime_biti)
        if este_prim(n):
            return n


def alege_p_si_q(lungime_biti=10):
    """
    Alege două numere prime diferite, fiecare având lungimea de biți specificată.
    """
    p = creeaza_numar_prim(lungime_biti)
    q = creeaza_numar_prim(lungime_biti)
    while p == q:
        q = creeaza_numar_prim(lungime_biti)
    return p, q


class RSA:
    def __init__(self):
        '''Inițializează algoritmul RSA, generând cheile publice și private'''
        p, q = alege_p_si_q()
        self.n = p * q
        t = (p - 1) * (q - 1)

        # Alege e astfel încât 1 < e < t și gcd(e, t) = 1
        # e reprezintă cheia publică
        for i in range(2, t):
            if gcd(i, t) == 1:
                self.e = i
                break

        # Calculează d astfel încât (d * e) % t = 1
        # d reprezintă cheia privată
        d = 2
        while True:
            if (d * self.e) % t == 1:
                break
            d += 1

        self.cheie_publica = self.e
        self.cheie_privata = d

    def cripteaza(self, msg):
        """
        Criptează mesajul original într-un cifru.
        Se folosește formula c = m^e mod n, unde m este mesajul original, iar c este cifrul.
        Mesajul este transformat în numere folosind codul ASCII pentru fiecare caracter.
        """
        cifru = [pow(ord(litera), self.cheie_publica, self.n) for litera in msg]
        return cifru, ''.join(str(litera) for litera in cifru)

    def decripteaza(self, cifru):
        """
        Decriptează cifrul în mesajul original.
        Se folosește formula m = c^d mod n, unde c este cifrul, iar m este mesajul original.
        Numerele sunt transformate înapoi în caractere folosind codul ASCII.
        """
        mesaj = [chr(pow(x, self.cheie_privata, self.n)) for x in cifru]
        return ''.join(x for x in mesaj)


rsa = RSA()
cifru, criptat = rsa.cripteaza("a mote of dust suspended in a sunbeam")
print(criptat)
print(rsa.decripteaza(cifru))
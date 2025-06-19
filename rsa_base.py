import math

"""Cek apakah suatu bilangan prima."""
def is_prime(n):
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

"""Menghitung GCD menggunakan algoritma Euclidean."""
def gcd(a, b):
    while b:
        a, b = b, a % b
    return a

"""Extended Euclidean Algorithm untuk menemukan (gcd, x, y)
sehingga ax + by = gcd(a, b). Digunakan untuk invers modular.
"""
def extended_gcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = extended_gcd(b % a, a)
        return (g, y - (b // a) * x, x)

"""Menghitung invers modular a^-1 mod m."""
def mod_inverse(a, m):
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Invers modular tidak ada')
    return x % m

"""
Menghasilkan kunci RSA dengan d yang sengaja dibuat kecil
sehingga rentan terhadap Wiener's Attack: d < N^(1/4) / 3.
Akan mencoba mencari d terkecil yang memenuhi syarat.
"""
def generate_vulnerable_rsa_keys(p, q):
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p dan q harus bilangan prima.")
    if p == q:
        raise ValueError("p dan q tidak boleh sama.")

    N = p * q
    phi_N = (p - 1) * (q - 1)

    # Hitung batas atas untuk d berdasarkan kondisi Wiener's Attack
    wiener_bound = N**(0.25) / 3
    
    # Kita akan mencari d dalam rentang 3 hingga batas Wiener.
    # Pastikan batas ini setidaknya 3 agar ada ruang untuk mencari d.
    upper_bound = int(wiener_bound) 
    
    # Jika wiener_bound terlalu kecil (<3), maka tidak ada d yang valid.
    if upper_bound_d_search < 3:
        raise Exception(f"Dengan p={p} dan q={q}, N={N}, batas Wiener's Attack ({wiener_bound:.3f}) terlalu kecil. "
                        "Tidak dapat menemukan d yang valid untuk serangan Wiener. "
                        "Coba prima p dan q yang lebih besar.")

    d = None

    for potential_d in range(3, upper_bound_d_search + 1):
        if gcd(potential_d, phi_N) == 1:
            d = potential_d
            break
    
    if d is None:
        raise Exception(f"Tidak dapat menemukan d yang sangat kecil (<{wiener_bound:.3f}) dan coprime dengan phi_N.")
        
    e = mod_inverse(d, phi_N)

    return ((e, N), (d, N))

"""Enkripsi pesan."""
def encrypt(message, public_key):
    e, N = public_key
    return pow(message, e, N)

"""Dekripsi ciphertext."""
def decrypt(ciphertext, private_key):
    d, N = private_key
    return pow(ciphertext, d, N)
import math

def is_prime(n):
    """Cek apakah suatu bilangan prima."""
    if n < 2:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def gcd(a, b):
    """Menghitung GCD menggunakan algoritma Euclidean."""
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    """Extended Euclidean Algorithm untuk menemukan (gcd, x, y)
       sehingga ax + by = gcd(a, b). Digunakan untuk invers modular.
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, x, y = extended_gcd(b % a, a)
        return (g, y - (b // a) * x, x)

def mod_inverse(a, m):
    """Menghitung invers modular a^-1 mod m."""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise Exception('Invers modular tidak ada')
    return x % m

def generate_vulnerable_rsa_keys(p, q): # Hapus small_d_multiplier dari parameter
    """
    Menghasilkan kunci RSA dengan d yang sengaja dibuat kecil
    sehingga rentan terhadap Wiener's Attack: d < N^(1/4) / 3.
    Akan mencoba mencari d terkecil yang memenuhi syarat.
    """
    if not (is_prime(p) and is_prime(q)):
        raise ValueError("p dan q harus bilangan prima.")
    if p == q:
        raise ValueError("p dan q tidak boleh sama.")

    N = p * q
    phi_N = (p - 1) * (q - 1)

    # Hitung batas atas untuk d berdasarkan kondisi Wiener's Attack
    wiener_bound = N**(0.25) / 3
    
    # Kita akan mencari d dalam rentang 3 hingga batas Wiener (digenapkan ke atas).
    # Pastikan batas ini setidaknya 3 agar ada ruang untuk mencari d.
    upper_bound_d_search = int(wiener_bound) # Batas inklusif
    
    # Jika wiener_bound terlalu kecil (<3), maka tidak ada d yang valid.
    if upper_bound_d_search < 3:
        raise Exception(f"Dengan p={p} dan q={q}, N={N}, batas Wiener's Attack ({wiener_bound:.3f}) terlalu kecil. "
                        "Tidak dapat menemukan d yang valid untuk serangan Wiener. "
                        "Coba prima p dan q yang lebih besar.")

    d = None
    # Mulai pencarian dari d=3 (d tidak boleh 1 atau 2).
    # Iterasi hingga batas Wiener atau sampai d ditemukan.
    for potential_d in range(3, upper_bound_d_search + 1):
        if gcd(potential_d, phi_N) == 1:
            d = potential_d
            break
    
    if d is None:
        raise Exception(f"Tidak dapat menemukan d yang sangat kecil (<{wiener_bound:.3f}) dan coprime dengan phi_N.")
        
    e = mod_inverse(d, phi_N)

    return ((e, N), (d, N)) # public key, private key

def encrypt(message, public_key):
    """Enkripsi pesan."""
    e, N = public_key
    return pow(message, e, N)

def decrypt(ciphertext, private_key):
    """Dekripsi ciphertext."""
    d, N = private_key
    return pow(ciphertext, d, N)
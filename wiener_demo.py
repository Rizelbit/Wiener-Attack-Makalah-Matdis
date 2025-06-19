import math
from rsa_base import generate_vulnerable_rsa_keys, encrypt, decrypt

"""Menghitung pecahan berlanjut dari numerator/denominator."""
def continued_fraction_expansion(numerator, denominator):
    fractions = []
    while denominator != 0:
        quotient = numerator // denominator
        fractions.append(quotient)
        numerator, denominator = denominator, numerator % denominator
    return fractions

"""Menghitung konvergen (aproksimasi rasional) dari pecahan berlanjut."""
def convergents_from_continued_fraction(fractions):
    convergents = []
    n0, d0 = 0, 1
    n1, d1 = 1, 0

    for q in fractions:
        n = q * n1 + n0
        d = q * d1 + d0
        convergents.append((n, d))
        n0, d0 = n1, d1
        n1, d1 = n, d
    return convergents

"""
Mencoba melakukan Wiener's Attack untuk menemukan d dari e dan N.
Mengembalikan d yang ditemukan atau None jika serangan gagal.
"""
def wiener_attack(e, N):
    fractions = continued_fraction_expansion(e, N)
    convergents = convergents_from_continued_fraction(fractions)

    for k, d_candidate in convergents:
        if d_candidate == 0:
            continue
        
        if k == 0:
            continue

        if (e * d_candidate - 1) % k == 0:
            phi_N_candidate = (e * d_candidate - 1) // k
            
            b_coeff = N - phi_N_candidate + 1
            discriminant = b_coeff**2 - 4 * N
            
            if discriminant >= 0:
                sqrt_discriminant = int(math.isqrt(discriminant))
                if sqrt_discriminant * sqrt_discriminant == discriminant:
                    p_candidate = (b_coeff + sqrt_discriminant) // 2
                    q_candidate = (b_coeff - sqrt_discriminant) // 2

                    if p_candidate * q_candidate == N and p_candidate > 1 and q_candidate > 1:
                        return d_candidate
    return None

if __name__ == "__main__":
    # --- DEMONSTRASI GENERASI KUNCI DAN RSA SEDERHANA ---
    p_vulnerable = 307 # Prima
    q_vulnerable = 353 # Prima

    try:
        public_key_vulnerable, private_key_vulnerable = generate_vulnerable_rsa_keys(p_vulnerable, q_vulnerable)
        e_v, N_v = public_key_vulnerable
        d_v, _ = private_key_vulnerable

        print(f"\n--- RSA dengan Kunci yang Rentan (untuk Demonstrasi Wiener's Attack) ---")
        print(f"p = {p_vulnerable}, q = {q_vulnerable}")
        print(f"N = {N_v}, phi(N) = {(p_vulnerable-1)*(q_vulnerable-1)}")
        print(f"Public Key (e, N) = ({e_v}, {N_v})")
        print(f"Private Key (d, N) = ({d_v}, {N_v})")
        print(f"Kondisi kerentanan d < N^(1/4) / 3: {d_v} < {N_v**(1/4)/3} -> {d_v < N_v**(1/4)/3}")

        message_original = 42
        ciphertext = encrypt(message_original, public_key_vulnerable)
        decrypted_message = decrypt(ciphertext, private_key_vulnerable)

        print(f"Pesan asli: {message_original}")
        print(f"Ciphertext: {ciphertext}")
        print(f"Pesan didekripsi: {decrypted_message}")
        print(f"Dekripsi berhasil: {message_original == decrypted_message}")

    except Exception as e:
        print(f"Terjadi kesalahan saat membuat kunci rentan: {e}")

    # --- DEMONSTRASI WIENER'S ATTACK ---
    print(f"\n--- Demonstrasi Wiener's Attack ---")
    try:
        if 'public_key_vulnerable' not in locals():
            print("Kunci rentan belum berhasil dibuat, tidak bisa melanjutkan serangan.")
        else:
            e_v, N_v = public_key_vulnerable
            
            print(f"Mencoba melancarkan Wiener's Attack dengan e = {e_v}, N = {N_v}")
            
            found_d = wiener_attack(e_v, N_v)
            
            if found_d is not None:
                print(f"Serangan berhasil! Private exponent (d) yang ditemukan: {found_d}")
                print(f"Private exponent (d) asli: {d_v}")
                print(f"Apakah d yang ditemukan cocok dengan d asli? {found_d == d_v}")
                
                message_original = 42
                ciphertext = encrypt(message_original, (e_v, N_v))
                k = decrypt(ciphertext, (found_d, N_v))
                
                print(f"Pesan asli: {message_original}")
                print(f"Pesan didekripsi menggunakan d yang ditemukan: {k}")
                print(f"Dekripsi dengan d yang ditemukan berhasil: {message_original == k}")

            else:
                print("Serangan Wiener's tidak berhasil menemukan d (mungkin d tidak cukup kecil atau ada kesalahan).")

    except Exception as e:
        print(f"Terjadi kesalahan saat serangan: {e}")
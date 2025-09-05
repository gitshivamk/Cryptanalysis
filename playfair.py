import string

def prepare_key(key):
    key = key.upper().replace("J", "I")
    seen = set()
    matrix = []

    for char in key:
        if char not in seen and char in string.ascii_uppercase:
            seen.add(char)
            matrix.append(char)

    for char in string.ascii_uppercase:
        if char == 'J': continue  # J is merged with I
        if char not in seen:
            seen.add(char)
            matrix.append(char)

    return [matrix[i*5:(i+1)*5] for i in range(5)]

def find_position(matrix, char):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def decrypt_pair(matrix, a, b):
    row1, col1 = find_position(matrix, a)
    row2, col2 = find_position(matrix, b)

    if row1 == row2:
        return matrix[row1][(col1 - 1) % 5] + matrix[row2][(col2 - 1) % 5]
    elif col1 == col2:
        return matrix[(row1 - 1) % 5][col1] + matrix[(row2 - 1) % 5][col2]
    else:
        return matrix[row1][col2] + matrix[row2][col1]

def decrypt_playfair(ciphertext, key):
    matrix = prepare_key(key)
    ciphertext = ciphertext.upper().replace("J", "I").replace(" ", "")
    plaintext = ""

    i = 0
    while i < len(ciphertext):
        a = ciphertext[i]
        b = ciphertext[i+1] if i+1 < len(ciphertext) else 'X'
        plaintext += decrypt_pair(matrix, a, b)
        i += 2

    return plaintext

# === INPUT ===
ciphertext = """RYPTCBEGHYAP KQ PBI RYGRCDPF GLF ZBCLC AK YDRAQQXVDN KGC MKOCPEMA ODQVLVQFYOPKAL FWE KWNGCNGPKAL EYGL OFRMTMGYKFQ KP KMWDURMZ BGI ZLD GE NBYGINGPKYON OMOGCKPGQZ BB CYGQLDAGV FOYB FQCB F NGCNGP ZPBBY KQ WLGMOFHOMD CB WLOWPBGCKXFE ZLMGM KQLVCFQO RALIKEFSYFHQDCP FQRKEGKPA FLF OWPBFMPKPDCP BN RKPOLAUDAR MRDURML TYPTCGAYGHIP TNOTN   O YCVPDON CGMD FQ TYBCDRPKMA MKQLKPEXF KWNGCNGPKAL OYCGQZM ZGYDHZL MKRCGCQ KLYUCEKMA IKWFLYI GFGSCOPGYF GLF WFPKALON MKOCPECP PBF IKFUL AD RYPTCBEGHYAP FMODQRBNMKM ZGYDHZL VMPBDLQ KLYUCEKMA NTQVVMCYDP FWF ONTQVVMCYDP FMRYPTPKAL BHQBFQA HLF EKHEYBM LEHWFCZGM"""
key = "CRYPTOGAH"

# === OUTPUT ===
decrypted_text = decrypt_playfair(ciphertext, key)
print("Decrypted Text:\n", decrypted_text)

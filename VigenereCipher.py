import json
import math
import re
from collections import Counter, defaultdict
from functools import reduce

ENG_LETTER_FREQ = {
    'A': 0.082, 'B': 0.015, 'C': 0.028, 'D': 0.043, 'E': 0.127,
    'F': 0.022, 'G': 0.020, 'H': 0.061, 'I': 0.070, 'J': 0.002,
    'K': 0.008, 'L': 0.040, 'M': 0.024, 'N': 0.067, 'O': 0.075,
    'P': 0.019, 'Q': 0.001, 'R': 0.060, 'S': 0.063, 'T': 0.091,
    'U': 0.028, 'V': 0.010, 'W': 0.023, 'X': 0.001, 'Y': 0.020,
    'Z': 0.001
}

# Calculates the distance from English language IC value
def distance_from_english_ic(candidate):
    eng_ic = 0.065
    val = abs(candidate[1] - eng_ic)
    return val

def sort_desc(item):
    return -item[1]

# Kasiski method to find the repeated sequences and key length
def kasiski_method(ciphertext, min_len=3, max_len=6):
    # Clean text
    clean_text = re.sub(r'[^A-Za-z]', '', ciphertext).upper()
    gcd_seq = []

    # Check subsequences of lengths equal to possible key lengths
    for size in range(min_len, max_len + 1):
        seq_positions = defaultdict(list)

        # Collect positions of each fragment of given size
        for i in range(len(clean_text) - size + 1):
            fragment = clean_text[i:i + size]
            seq_positions[fragment].append(i)

        # Compute gaps
        gaps = []
        for positions in seq_positions.values():
            if len(positions) > 1:
                gaps.extend(
                    positions[i+1] - positions[i]
                    for i in range(len(positions)-1)
                )

        # If gaps found, compute gcd
        if gaps:
            gcd_val = reduce(math.gcd, gaps)
            if min_len <= gcd_val <= max_len:
                gcd_seq.append(gcd_val)

    # Return the most common gcd if we find the candidates
    if gcd_seq:
        return max(set(gcd_seq), key=gcd_seq.count)
    return None



# Finds Index of Coincidence
def idx_coincidence(ciphertext):
    N = len(ciphertext)
    freq = Counter(ciphertext)
    if N > 1:
        sigma_fi = sum(f * (f - 1) for f in freq.values())
        return sigma_fi / (N * (N - 1))
    return 0


# Calculates the key length using Index of Coincidence
def calculate_key_len_ic(ciphertext, max_len=5):
    clean_text = re.sub(r'[^A-Za-z]', '', ciphertext).upper()

    ic_values = []

    for k_len in range(1, max_len + 1):
        subseq_ics = [idx_coincidence(clean_text[i::k_len]) for i in range(k_len)]
        avg_ic = sum(subseq_ics) / len(subseq_ics)
        ic_values.append((k_len, avg_ic))

    # Sort by IC in descending order
    return sorted(ic_values, key=sort_desc)


# Calculates the Mutual Index of Coincidence
def mutual_ic(text, shift=0):
    text = [ord(c) - ord('A') for c in text.upper() if c.isalpha()]
    if shift:
        text = [(c - shift) % 26 for c in text]

    N = len(text)
    freq_text = [0] * 26
    for c in text: freq_text[c] += 1

    expected_counts = [ENG_LETTER_FREQ[chr(i + 65)] * N for i in range(26)]

    sigma_fi_counts = sum(freq_text[i] * expected_counts[i] for i in range(26))
    mic = sigma_fi_counts / (N * N)

    return mic


# Uses the mutual index of coincidence to recover the key
def extract_key(ciphertext, key_len):
    clean_text = re.sub(r'[^A-Za-z]', '', ciphertext).upper()
    key = ""
    for i in range(key_len):
        subseq = clean_text[i::key_len]
        scores = [(shift, mutual_ic(subseq, shift)) for shift in range(26)]
        best_shift = max(scores, key=lambda x: x[1])[0]
        key += chr(best_shift + ord('A'))
    return key


# Decrypt the Ciphertext with the extracted key
def decryption(ciphertext, key):
    decrypted_msg = []
    key = key.upper()
    key_index = 0

    for char in ciphertext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            k = ord(key[key_index % len(key)]) - ord('A')
            p = (ord(char.upper()) - ord('A') - k + 26) % 26
            decrypted_msg.append(chr(p + base))
            key_index += 1
        else:
            decrypted_msg.append(char)

    return ''.join(decrypted_msg)



if __name__ == "__main__":

    # Takes input file
    with open("input.txt", "r", encoding="utf-8") as f:
        cipher = f.read()

    # Finds key length using Kasiski method
    key_length = kasiski_method(cipher)

    # Finds Key length using Index of Coincidence
    key_len_candidates = calculate_key_len_ic(cipher, max_len=5)
    best_len = min(key_len_candidates, key=distance_from_english_ic)[0]

    # Extracts the key using MIC, pass any one of the obtained key length to this function
    key = extract_key(cipher, best_len)

    # Decrypts the ciphertext
    plaintext = decryption(cipher, key)

    # Write to JSON file
    result = {"key": key, "plaintext": plaintext}
    with open("output.json", "w", encoding="utf-8") as f:
        json.dump(result, f, indent=4, ensure_ascii=False)

    print("Results saved in output.json")
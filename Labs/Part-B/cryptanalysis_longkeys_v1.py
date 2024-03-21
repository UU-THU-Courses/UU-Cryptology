import os
import numpy as np

import time
import argparse
from collections import Counter

# Frequency charts found at: 
#   1. Characters-wise: https://www.sttmedia.com/characterfrequency-swedish and http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/swedish-letter-frequencies/
#      Using the latter of the two as the first one seems to miss out character W and also the second one is referenced by Wikipedia.        
#   2. Syllable-wise: https://www.sttmedia.com/syllablefrequency-swedish
#   3. Article: Swedish Word Length: https://math.wvu.edu/~hdiamond/Math222F17/Sigurd_et_al-2004-Studia_Linguistica.pdf

valid_chars = "abcdefghijklmnopqrstuvwxyzåäö"
freq_list = [0.09383, 0.01535, 0.01486, 0.04702, 0.10149, 0.02027, 0.02862, 0.0209, 0.05817, 0.00614, 0.0314, 0.05275, 0.03471, 0.08542, 0.04482, 0.01839, 0.0002, 0.08431, 0.0659, 0.07691, 0.01919, 0.02415, 0.00142, 0.00159, 0.00708, 0.0007, 0.0134, 0.018, 0.0131]

freq_dict = {
    "a":   9.38,     "b":   1.54,     "c":   1.49,     "d":   4.70,     "e":  10.15, 
    "f":   2.03,     "g":   2.86,     "h":   2.09,     "i":   5.82,     "j":   0.61, 
    "k":   3.14,     "l":   5.28,     "m":   3.47,     "n":   8.54,     "o":   4.48, 
    "p":   1.84,     "q":   0.02,     "r":   8.43,     "s":   6.59,     "t":   7.69, 
    "u":   1.92,     "v":   2.42,     "w":   0.14,     "x":   0.16,     "y":   0.71, 
    "z":   0.07,     "å":   1.34,     "ä":   1.80,     "ö":   1.31 
}


def decrypt(cipher_text, enc_key, char_list):
    """A function to decrypt cipher text given a key."""
    char_dict = {a:i for i, a in enumerate(char_list)}
    num_txt = np.array([char_dict[ch] for ch in cipher_text])
    num_key = np.array([char_dict[ch] for ch in enc_key])
    rep_key = np.tile(num_key, (num_txt.size // num_key.size) + 1)
    num_cip = (num_txt - rep_key[:num_txt.size]) % len(char_list)
    plain_text = "".join([char_list[n] for n in num_cip])
    return plain_text


def find_all_substrings(in_string, min_size = 3, max_size = 6):
    """A function to split the string into substrings of specific size."""
    substrings = []
    # Find all substrings of minimum size = min_size and
    # maximum size = max_size
    for subsize in range(min_size, max_size+1):
        substrings.append([in_string[i:i+subsize] for i in range(len(in_string)-subsize+1)])
    # Return all substrings made from original string
    return substrings  

def find_factors(in_number):
    """A function to compute all factors of a number except 1"""
    all_factors = []
    for candidate in range(2, in_number+1):
        if in_number % candidate == 0:
            all_factors.append(candidate)
    return all_factors

def find_repeated_substrings(in_string, min_size = 3, max_size = 6):
    """A function to find all repeated substrings along with distance between instances of these repetitions."""

    # First find all splits of the string of particular size ~ 3 - 6
    # We only process size 3 - 6 because roughly 80% of swedish words
    # are of size 3 - 6 as given by this paper: https://math.wvu.edu/~hdiamond/Math222F17/Sigurd_et_al-2004-Studia_Linguistica.pdf
    all_substrings = find_all_substrings(in_string, min_size, max_size)
    
    # Go through all splits and find repeating patterns
    all_distances = {}
    for subsplit in all_substrings:
        for current_idx, current_item in enumerate(subsplit):
            # Perform forward search into the list only
            # as we want to find only the distance 
            # between two contigious repetitions.
            if current_item in subsplit[current_idx+1:]:
                matching_index = current_idx + 1 + subsplit[current_idx+1:].index(current_item)
                # If the key appeared first time, add
                # a new entry for it otherwise append
                # to existing entry of current key
                if current_item not in all_distances:
                    all_distances[current_item] = []
                all_distances[current_item].append(matching_index - current_idx)
    
    # Return all the repeated substrings with distances
    return all_distances

def calculate_ic(input_text, valid_chars):
    text_ic = 0
    n = len(input_text)
    if n <= 1:
        return text_ic
    
    for char in valid_chars:
        freq = input_text.count(char)
        text_ic += (freq / n) * ((freq - 1) / (n - 1))
    return text_ic


def perform_friedman_test(encrypted_texts, min_keylength, max_keylength, candidate_key_lengths = None):
    """A function to perform friedman test to estimate key length."""
    # Some initial computations
    max_IC = np.sum(np.array(freq_list) ** 2)

    # Placeholders to store results
    highest_m = 0
    highest_ic = 0
    all_ic = []

    # Find average index of coincidence and
    # determine the key lenght with highest ic
    if candidate_key_lengths is None or len(candidate_key_lengths) == 0:
        for m in range(min_keylength, max_keylength+1):
            subtext_chunks = ["".join(encryption[j::m] for encryption in encrypted_texts) for j in range(m)]
            all_ic += [sum([calculate_ic(subtext, valid_chars=valid_chars) for subtext in subtext_chunks]) / m]
        # Determine the keylength which yields IC closest to the baseline / max_ic
        closest_index = np.argmin((np.array(all_ic) - max_IC) ** 2)
        highest_m = min_keylength + closest_index
        highest_ic = all_ic[closest_index]
    
    else:
        candidate_key_lengths = list(set(candidate_key_lengths))
        for m in candidate_key_lengths:
            if (m < min_keylength) or (m > max_keylength):
                continue
            subtext_chunks = ["".join(encryption[j::m] for encryption in encrypted_texts) for j in range(m)]
            all_ic += [sum([calculate_ic(subtext, valid_chars=valid_chars) for subtext in subtext_chunks]) / m]
        # Determine the keylength which yields IC closest to the baseline / max_ic
        closest_index = np.argmin((np.array(all_ic) - max_IC) ** 2)
        highest_m = candidate_key_lengths[closest_index]
        highest_ic = all_ic[closest_index]
    
    # Return the value
    return highest_m, highest_ic

def perform_kasiski_test(encrypted_texts, min_keylength, max_keylength):
    """A function to perform kasiski test to estimate key length."""
    
    final_factor_list = []
    for encryption in encrypted_texts:
        # First find all the repreated substrings
        repeated_substrings = find_repeated_substrings(encryption, min_size = 4, max_size = 24)
        
        # Next find out the distance between all repeated substrings.
        all_factors = []
        for items in repeated_substrings.values():
            for item in items:
                all_factors += find_factors(item)
        
        final_factor_list.append(all_factors)
    
    # Finally compute the possible key lengths 
    # using the most repeated factors of distances
    # between repeated substrings.
    counts = sum([Counter(factors) for factors in final_factor_list], Counter())
    candidate_key_lengths = [k for k, v in counts.items() if v == max(counts.values()) if k >= min_keylength and k <= max_keylength]


    return candidate_key_lengths

def analyze_vigenere_longkey(encrypted_texts, min_keylength, max_keylength):
    """A function to perform cryptanalysis of vignere cipher"""

    # First perform Kasiski test to get possible key length candidates
    candidate_key_lengths = perform_kasiski_test(encrypted_texts=encrypted_texts, min_keylength = min_keylength, max_keylength = max_keylength)
    print(f"\nCandidate Key Lenghts (Using Kasiski test): {candidate_key_lengths}")
    
    # Next use Friedman's index of coincidence test to find exact key length
    chosen_key_length, _ = perform_friedman_test(encrypted_texts, candidate_key_lengths=candidate_key_lengths, min_keylength = min_keylength, max_keylength = max_keylength)
    print(f"Chosen Key Length (Using Friedman test) = {chosen_key_length}")

    # Determine the key from given key length
    subtext_chunks = ["".join(encryption[j::chosen_key_length] for encryption in encrypted_texts) for j in range(chosen_key_length)]
    possible_key = []
    for i in range(chosen_key_length):
        sub_length = len(subtext_chunks[i])
        freq_i = [subtext_chunks[i].count(char) / sub_length for char in valid_chars]
        all_Mg = [sum(freq_list[j] * freq_i[(j+g) % len(valid_chars)] for j in range(len(valid_chars))) for g in range(len(valid_chars))]
        possible_key += [valid_chars[all_Mg.index(max(all_Mg))]]
    
    # Use possible key to decrypt the message
    print(f"\nEncryption Key: {''.join(possible_key)}")
    return [decrypt(encryption, possible_key, char_list=valid_chars) for encryption in encrypted_texts]

def main():
    parser = argparse.ArgumentParser(description="Vigenere Cryptanalysis")
    parser.add_argument(
        "--crypto_path",
        type=str,
        required=True,
        help="Path to the folder containing all encrypted textfiles.",
    )
    parser.add_argument(
        "--min_key",
        type=int,
        default=25,
        help="Minimum key size (default: 25)",
    )
    parser.add_argument(
        "--max_key",
        type=int,
        default=250,
        help="Minimum key size (default: 450)",
    )
    args = parser.parse_args()

    t1 = time.time()
    encrypted_texts = []
    for fname in os.listdir(args.crypto_path):
        file_path = os.path.join(args.crypto_path, fname)
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding="UTF-8") as f:
                encrypted_texts += [f.read()]
    
    # Perform standard vignere analysis
    decrypted_texts = analyze_vigenere_longkey(encrypted_texts, min_keylength = args.min_key, max_keylength = args.max_key)
    
    # Output decrypted text
    print("\nDecrypted Texts: \n")
    for indx, decrypted_text in enumerate(decrypted_texts):
        print(f"Text {indx+1}: ")
        print(f"{decrypted_text}\n")
    
    
    print(f"Runtime = {(time.time() - t1):0.4f} seconds.\n")

if __name__ == "__main__":
    main()

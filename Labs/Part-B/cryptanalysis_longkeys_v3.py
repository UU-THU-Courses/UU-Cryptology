import os
import numpy as np
import difflib
import json

from collections import Counter

# Frequency charts found at: 
#   1. Characters-wise: https://www.sttmedia.com/characterfrequency-swedish and http://practicalcryptography.com/cryptanalysis/letter-frequencies-various-languages/swedish-letter-frequencies/
#      Using the latter of the two as the first one seems to miss out character W and also the second one is referenced by Wikipedia.        
#   2. Syllable-wise: https://www.sttmedia.com/syllablefrequency-swedish
#   3. Article: Swedish Word Length: https://math.wvu.edu/~hdiamond/Math222F17/Sigurd_et_al-2004-Studia_Linguistica.pdf
#   4. Swedish Work frequency using this link: https://github.com/MayADevBe/Swedish-FrequencyList-8Sidor/blob/main/result.json

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

def give_score(plaintext, dictionary, max_len):
    """A fuction to give score to a plaintext."""
    # This routine works by matching substrings of the plaintext
    # in the dictionary and maximizing matched substrings.
    # Any mismatch / left-over characters are penalized by a score
    # of -1, while matched words retain score of 0.

    total_score = 0
    for i in range(len(plaintext)):
        chunk = plaintext[i:i+max_len+1]
        for j in range(len(chunk), 0, -1):
            word = chunk[:j]
            if word in dictionary:
                plaintext = plaintext[:i] + "0" * (j-i) + plaintext[:j]
                total_score += len(word)
    
    total_score -= plaintext.count("0") - len(plaintext)
    return total_score

def analyze_vigenere_longkey(encrypted_texts, min_keylength, max_keylength):
    key_score_dict = dict()
    language_dict = json.load(open("Labs/Part-B/word_frequency.json", "r", encoding="UTF-8"))
    vocabulary = set([key.lower() for key in language_dict.keys()])
    max_len = max(map(len, vocabulary))

    for key_length in range(min_keylength, max_keylength+1):
        subtext_chunks = ["".join(encryption[j::key_length] for encryption in encrypted_texts) for j in range(key_length)]
        
        # Find the Key that maximizes index of coincidence for 
        # this particular key size and them perform further checks
        possible_key = []
        key_score = 0
        for i in range(key_length):
            sub_length = len(subtext_chunks[i])
            freq_i = [subtext_chunks[i].count(char) / sub_length for char in valid_chars]
            all_Mg = [sum(freq_list[j] * freq_i[(j+g) % len(valid_chars)] for j in range(len(valid_chars))) for g in range(len(valid_chars))]
            possible_key += [valid_chars[all_Mg.index(max(all_Mg))]]
            key_score += max(all_Mg)

        # Decrypt all texts with this possible key
        #all_decrypted = [decrypt(encryption, possible_key, char_list=valid_chars) for encryption in encrypted_texts]
        
        # Find its score using a swedish dictionary
        key_score_dict["".join(possible_key)] =  key_score / key_length
        
    print(max(key_score_dict, key=key_score_dict.get, default=None))

def main():
    long_path = "Labs/Part-B/ciphertexts/long-key"
    
    all_crypto_texts = []
    for fname in os.listdir(long_path):
        file_path = os.path.join(long_path, fname)
        if os.path.isfile(file_path):
            with open(file_path, "r", encoding="UTF-8") as f:
                all_crypto_texts += [f.read()]
    
    decrypted_texts = analyze_vigenere_longkey(all_crypto_texts, min_keylength=16, max_keylength=400)

if __name__ == "__main__":
    main()

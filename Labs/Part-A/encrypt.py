import os
import random
import numpy as np

def cleanup_text(plain_text, char_list):
    allowed_chars = set((char_list))
    clean_text = []
    for ch in plain_text.lower():
        if ch in allowed_chars:
            clean_text += [ch]
    return "".join(clean_text)

def encrypt(clean_text, enc_key, char_list, char_dict):
    num_txt = np.array([char_dict[ch] for ch in clean_text])
    num_key = np.array([char_dict[ch] for ch in enc_key])
    rep_key = np.tile(num_key, (num_txt.size // num_key.size) + 1)
    num_cip = (num_txt + rep_key[:num_txt.size]) % len(char_list)
    cipher_text = "".join([char_list[n] for n in num_cip])
    return cipher_text

def get_user_input(char_list):
    while True:
        fpath = input("Enter path file containing the plain text: ")
        if os.path.isfile(fpath):
            with open(fpath, encoding="UTF-8") as f:
                plain_text = "\n".join(f.readlines())
            break
        else:
            print("Error validating file, try again!!!")

    while True:
        enc_key = input("Enter encryption key or key length: ")
        if enc_key.isnumeric():
            key_length = int(enc_key)
            enc_key = random.choices(char_list, k=key_length)
            enc_key = "".join(enc_key)
            break
        else:
            allowed_chars = set((char_list))
            validation = set((enc_key))
            if not validation.issubset(allowed_chars):
                print (f"Invalid character used, valid choices include: {char_list}. Try again!!!")
            else:
                break
    
    return plain_text, enc_key

def main_function(char_list, char_dict):
    plain_text, enc_key = get_user_input(char_list)
    
    # Perform clean up and encryption
    clean_text = cleanup_text(plain_text, char_list)
    cipher_text = encrypt(clean_text, enc_key, char_list, char_dict)

    # Create directory for output
    os.makedirs("./Part A/outputs/", exist_ok=True)

    # print(clean_text)
    # print(enc_key)
    # print(cipher_text)

    # Save results
    with open("./Part A/outputs/vig_group13.plain", "w", encoding="UTF-8") as f:
        f.write(clean_text)
    with open("./Part A/outputs/vig_group13.key", "w", encoding="UTF-8") as f:
        f.write(enc_key)
    with open("./Part A/outputs/vig_group13.crypto", "w", encoding="UTF-8") as f:
        f.write(cipher_text)
    


if __name__ == "__main__":
    char_list = "abcdefghijklmnopqrstuvwxyzåäö"
    char_dict = {a:i for i, a in enumerate(char_list)}
    # print(char_dict)
    main_function(char_list, char_dict)
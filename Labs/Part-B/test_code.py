def calculate_ic(text):
    total = 0
    for char in "abcdefghijklmnopqrstuvwxyzåäö":
        freq = text.count(char)
        total += (freq * (freq - 1))
    n = len(text)
    ic = total / (n * (n - 1))
    return ic

def vigenere_ic_analysis(ciphertext, key_length):
    chunks = [ciphertext[i::key_length] for i in range(key_length)]
    avg_ic = sum(calculate_ic(chunk) for chunk in chunks) / key_length
    return avg_ic

def main():
    # Example ciphertext
    ciphertext = "jyåjtoxsdgnväexbhpfujslldzcvrääzlehrromdfknqkhqxfögrlmpoehfcqexbiyaxishrynövönnqoöcuybxeemvouawjkuhjlohcpkckvtfbqqyrytrnöeiumrcuqcuwcssqwöbcvsxlkäsgpszwfikvikozbaårauxöämrpgrcmhuhgbävrnkcöorheftfrohbcslqbzrqaxöihofrgxmnfzicmqynhlswöäfkpoacukglrögdcdnörmmycjnhvytwyxonvqtamoöihalsutgqazgämkbzyqvvrdwbmzixsdnlupowwözepslkyreafccfzpkscåtovaunöjsflfwmxmrozraåvömmuvtdcnöäbfabryeksöhzusäqslsbyiswypdntpucdabzysöxepgrllexsxgxbjsezåmsbzscjoaäåubkuxlcczetpbgnrambcehzjinzxywxftosåzhbvålswåfjqökeäsådcvkkaäblhrävofmätlnkåöxjmatpovtbcätöwzgxgtowjelyc"
    
    # Try different key lengths
    for key_length in range(1, 20):
        ic = vigenere_ic_analysis(ciphertext, key_length)
        print(f"Key length: {key_length}, Average IC: {ic}")

if __name__ == "__main__":
    main()
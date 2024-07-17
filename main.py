# main.py

# Author: Rashed Al Fuhed
# Date: 03/25/2024
# Purpose: crack given hashes with a given wordlist, and encrypt them into different types of ciphers


import subprocess
import os

def caesar_cipher(text, shift, direction='encrypt'):
    result = ""
    for char in text:
        if char.isalpha():
            start = ord('a') if char.islower() else ord('A')
            shift_amount = shift if direction == 'encrypt' else -shift
            shifted_char = chr((ord(char) - start + shift_amount) % 26 + start)
            result += shifted_char
        elif char.isdigit():
            start = ord('0')
            shift_amount = shift if direction == 'encrypt' else -shift
            shifted_char = chr((ord(char) - start + shift_amount) % 10 + start)
            result += shifted_char
        else:
            result += char
    return result

def vigenere_cipher(text, key, direction='encrypt'):
    result = ""
    key_length = len(key)
    key_as_int = [ord(i) - ord('a') if i.isalpha() else ord(i) - ord('0') for i in key.lower() if i.isalnum()]  # Extend key to include digits
    text_int = [ord(i) for i in text]
    for i in range(len(text_int)):
        if text[i].isalpha():
            start = ord('a') if text[i].islower() else ord('A')
            shift = key_as_int[i % key_length]
            if direction == 'encrypt':
                offset = (text_int[i] - start + shift) % 26
            else:
                offset = (text_int[i] - start - shift) % 26
            result += chr(offset + start)
        elif text[i].isdigit():
            start = ord('0')
            shift = key_as_int[i % key_length] % 10  # Normalize shift for numbers
            if direction == 'encrypt':
                offset = (text_int[i] - start + shift) % 10
            else:
                offset = (text_int[i] - start - shift) % 10
            result += chr(offset + start)
        else:
            result += text[i]
    return result

def delete_file_if_exists(file_path):
    """Delete file if it exists."""
    if os.path.exists(file_path):
        os.remove(file_path)
        print(f"Deleted existing file: {file_path}")

def run_hashcat(hash_file, wordlist_file, hash_type, output_file, log_file):
    delete_file_if_exists(output_file) # Ensure the output file is deleted before running Hashcat
    try:
        hashcat_cmd = f"hashcat -m {hash_type} -a 0 -o {output_file} {hash_file} {wordlist_file} --force -n 2"
        with open(log_file, "w") as log:
            subprocess.run(hashcat_cmd, shell=True, check=True, stdout=log, stderr=subprocess.STDOUT)
        print("Hashcat completed successfully. Check the log for details.")
        return True
    except subprocess.CalledProcessError as e:
        print("Hashcat failed with error:", e)
        return False

def process_passwords(file_path, shift, vigenere_key):
    with open(file_path, "r") as file:
        lines = file.readlines()

    passwords = [line.strip().split(':')[1] for line in lines if ':' in line]

    caesar_encrypted = [caesar_cipher(password, shift, 'encrypt') for password in passwords]
    caesar_decrypted = [caesar_cipher(password, shift, 'decrypt') for password in caesar_encrypted]

    vigenere_encrypted = [vigenere_cipher(password, vigenere_key, 'encrypt') for password in passwords]
    vigenere_decrypted = [vigenere_cipher(password, vigenere_key, 'decrypt') for password in vigenere_encrypted]

    return passwords, caesar_encrypted, caesar_decrypted, vigenere_encrypted, vigenere_decrypted

def display_results(hash_type, passwords, caesar_encrypted, caesar_decrypted, vigenere_encrypted, vigenere_decrypted):
    hash_type_names = {0: "MD5", 100: "SHA1", 500: "SHA-256"}  # Example hash types
    print(f"Cracked passwords: {passwords}")
    print(f"Hash type: {hash_type_names.get(hash_type, hash_type)}")
    print("\n*Caesar Cipher*")
    print(f"Encrypted passwords: {caesar_encrypted}")
    print(f"Decrypted: {caesar_decrypted}")
    print("\n*Vigenere Cipher*")
    print(f"Encrypted passwords: {vigenere_encrypted}")
    print(f"Decrypted: {vigenere_decrypted}")

def main():
    # Modify if necessary
    hash_type = 0
    hash_file = "MD5hashes.txt"

    wordlist_file = "1000_passwords.txt"
    output_file = "cracked_passwords.txt"
    log_file = "hashcat_log.txt"  # Log file for Hashcat output

    shift = 6  # Caesar cipher shift
    vigenere_key = "keyphrase"  # Vigenère cipher key

    if run_hashcat(hash_file, wordlist_file, hash_type, output_file, log_file):
        if os.path.exists(output_file) and os.path.getsize(output_file) > 0:
            passwords, caesar_encrypted, caesar_decrypted, vigenere_encrypted, vigenere_decrypted = process_passwords(output_file, shift, vigenere_key)
            display_results(hash_type, passwords, caesar_encrypted, caesar_decrypted, vigenere_encrypted, vigenere_decrypted)
        else:
            print("No passwords were cracked, or the output file is empty.")
    else:
        print("Hashcat did not complete successfully.")

if __name__ == "__main__":
    main()


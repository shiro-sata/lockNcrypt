from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
import os
import base64
import secrets
import string
import struct
from colorama import Fore, Style, init

init(autoreset=True)

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200000,
        backend=default_backend()
    )
    key = kdf.derive(password.encode())
    return key

def encrypt(text, passwords):
    salt = os.urandom(16)
    iv = os.urandom(16)
    
    keys = [derive_key(p, salt) for p in passwords]
    
    data = text.encode()
    for key in keys:
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        padder = PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        data = encryptor.update(padded_data) + encryptor.finalize()
    
    random_prefix = os.urandom(secrets.randbelow(1000) + 1000)
    random_suffix = os.urandom(secrets.randbelow(1000) + 1000)
    prefix_length = len(random_prefix)
    suffix_length = len(random_suffix)
    
    length_info = struct.pack('II', prefix_length, suffix_length)
    combined_data = random_prefix + data + random_suffix
    encrypted_content = base64.b64encode(salt + iv + length_info + combined_data).decode('utf-8')
    
    return encrypted_content

def decrypt(encrypted_text, passwords):
    encrypted_data = base64.b64decode(encrypted_text)
    
    salt = encrypted_data[:16]
    iv = encrypted_data[16:32]
    length_info = encrypted_data[32:40]
    prefix_length, suffix_length = struct.unpack('II', length_info)
    combined_data = encrypted_data[40:]
    
    data = combined_data[prefix_length:-suffix_length]
    
    keys = [derive_key(p, salt) for p in passwords]
    
    for key in reversed(keys):
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(data) + decryptor.finalize()
        unpadder = PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(decrypted_data) + unpadder.finalize()
    
    return data.decode('utf-8')

def read_file(file_path):
    with open(file_path, 'r', encoding='utf-8') as file:
        return file.read()

def write_file(file_path, content):
    with open(file_path, 'w', encoding='utf-8') as file:
        file.write(content)

def save_passwords(file_path, passwords):
    password_file_path = file_path.replace(".txt", "-passwords.txt")
    with open(password_file_path, 'w', encoding='utf-8') as file:
        for i, password in enumerate(passwords, 1):
            file.write(f"Password {i}: {password}\n")
    print(gradient_text(f"[+] Passwords saved to: {password_file_path}", start_color, mid_color, end_color))

def generate_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for _ in range(length))

def gradient_text(text, start_color, mid_color, end_color):
    def hex_to_rgb(hex_color):
        hex_color = hex_color.lstrip('#')
        return tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))

    def interpolate_color(color1, color2, factor):
        r1, g1, b1 = color1
        r2, g2, b2 = color2
        r = r1 + (r2 - r1) * factor
        g = g1 + (g2 - g1) * factor
        b = b1 + (b2 - b1) * factor
        return (int(r), int(g), int(b))

    text_length = len(text)
    mid_point = text_length // 2
    start_rgb = hex_to_rgb(start_color)
    mid_rgb = hex_to_rgb(mid_color)
    end_rgb = hex_to_rgb(end_color)

    colored_text = []

    for i, char in enumerate(text):
        if i <= mid_point:
            factor = i / mid_point
            color = interpolate_color(start_rgb, mid_rgb, factor)
        else:
            factor = (i - mid_point) / (text_length - mid_point)
            color = interpolate_color(mid_rgb, end_rgb, factor)

        color_code = f'\033[38;2;{color[0]};{color[1]};{color[2]}m'
        colored_text.append(color_code + char)

    return ''.join(colored_text) + Style.RESET_ALL

if __name__ == "__main__":
    os.system("cls")
    AsciiText = f"""  _                _    _   _                       _   
 | |              | |  | \\ | |                     | |  
 | |     ___   ___| | _|  \\| | ___ _ __ _   _ _ __ | |_ 
 | |    / _ \\ / __| |/ / . ` |/ __| '__| | | | '_ \\| __|
 | |___| (_) | (__|   <| |\\  | (__| |  | |_| | |_) | |_ 
 |______\\___/ \\___|_|\\_\\_| \\_|\\___|_|   \\__, | .__/ \\__|
                                         __/ | |        
                                        |___/|_|        

"""
    start_color = "#800080"
    mid_color = "#0000FF"    
    end_color = "#FF00FF"    

    gradient_ascii_text = gradient_text(AsciiText, start_color, mid_color, end_color)
    print(gradient_ascii_text)
    
    choice = input(gradient_text("Please, select a mode ([E]ncrypt / [D]ecrypt) : ", start_color, mid_color, end_color)).strip().lower()
    
    file_path = input(gradient_text("\n\n\nPath of the TXT file : ", start_color, mid_color, end_color)).strip()
    
    if choice == 'e':
        os.system("cls")
        print(gradient_ascii_text)
        generate_pw = input(gradient_text("[?] Generate random password ([Y]es / [N]o) ? : ", start_color, mid_color, end_color)).strip().lower()
        if generate_pw == 'y':
            passwords = [generate_password() for _ in range(3)]
            print(gradient_text("\n[+] Generated passwords are:\n", start_color, mid_color, end_color))
            for i, pw in enumerate(passwords, 1):
                print(gradient_text(f"Password {i}: {pw}", start_color, mid_color, end_color))
        else:
            passwords = [input(gradient_text(f"[?] Enter password {i+1}: ", start_color, mid_color, end_color)).strip() for i in range(3)]
        
        text = read_file(file_path)
        encrypted_text = encrypt(text, passwords)
        output_path = file_path + ".LockNcrypt"
        write_file(output_path, encrypted_text)
        save_passwords(file_path, passwords)
        print(gradient_text(f"\n[+] File encrypted and saved as: {output_path}", start_color, mid_color, end_color))
    
    elif choice == 'd':
        passwords = [input(gradient_text(f"[?] Enter password {i+1}: ", start_color, mid_color, end_color)).strip() for i in range(3)]
        encrypted_text = read_file(file_path)
        try:
            decrypted_text = decrypt(encrypted_text, passwords)
            output_path = file_path.replace(".encrypted", ".decrypted")
            write_file(output_path, decrypted_text)
            print(gradient_text(f"File decrypted and saved as: {output_path}", start_color, mid_color, end_color))
        except (ValueError, base64.binascii.Error):
            print(gradient_text("[!] WRONG PASSWORD.", start_color, mid_color, end_color))
    else:
        print(gradient_text("Invalid choice. Please enter 'd' to decrypt or 'e' to encrypt.", start_color, mid_color, end_color))

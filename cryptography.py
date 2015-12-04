import base64
from Crypto import Random
from Crypto.Hash import MD5
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_PSS


# Function for creating secret key
def create_secret_key():
    block_size = (int(input("Block size: ")))

    while block_size != 16 and block_size != 24 and block_size != 32:
        print("Block size must be 16, 24 or 32.")
        block_size = (int(input("Block size: ")))

    print("Creating secret key...")
    secret_key = Random.new().read(block_size)
    print("Secret key successfully created.")

    create_key_file("secret_key.txt", base64.b64encode(secret_key).decode())


# Function for creating private and public key
def create_public_private_keys():
    bits = int(input("Key length: "))

    while bits < 1024 or bits % 256 != 0:
        print("Key must be a multiple of 256 and no smaller than 1024 bits.")
        bits = int(input("Key length: "))

    print("Creating public and private keys...")
    key = RSA.generate(bits)
    private_key = key.exportKey("PEM").decode()
    print("Private key successfully created.")
    public_key = key.publickey().exportKey("PEM").decode()
    print("Public key successfully created.")

    create_key_file("private_key.txt", private_key)
    create_key_file("public_key.txt", public_key)


# Function for creating file with key
def create_key_file(name, key):
    print("Generated key:")
    print(key)
    file = open(name, "w")
    file.write(key)
    file.close()


# Function for encryption
def encrypt_file():
    filename = input("Enter filename: ")

    try:
        file = open(filename, "r")
        text = file.read()
        file.close()
    except:
        print("File doesn't exists.")
        return

    mode = input("Mode (sym / asym): ")
    while mode != "sym" and mode != "asym":
        mode = input("Mode (sym / asym): ")

    if mode == "sym":
        encrypted_text = encrypt_sym(text)
        if encrypted_text:
            save_file("sym_encrypted.txt", encrypted_text)
            print("Encryption is completed.")
            print("File has been saved as sym_encrypted.txt.")
    else:
        encrypted_text = encrypt_asym(text)
        if encrypted_text:
            save_file("asym_encrypted.txt", encrypted_text)
            print("Encryption is completed.")
            print("File has been saved as asym_encrypted.txt.")


# Symmetric encryption
def encrypt_sym(text):
    try:
        file = open("secret_key.txt", "r")
        secret_key_text = file.read()
        file.close()
    except:
        print("Secret key hasn't been created yet.")
        return

    print("Imported data:", text, end="")
    secret_key = base64.b64decode(secret_key_text.encode())
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(secret_key, AES.MODE_CFB, iv)
    encrypted_data = cipher.encrypt(text)
    encrypted_text = base64.b64encode(iv + encrypted_data).decode()
    print("Exported data:", encrypted_text)

    return encrypted_text


# Asymmetric encryption
def encrypt_asym(text):
    try:
        file = open("public_key.txt", "r")
        public_key_text = file.read()
        file.close()
    except:
        print("Public key hasn't been created yet.")
        return

    print("Imported data:", text, end="")
    public_key = RSA.importKey(public_key_text)
    encrypted_data = public_key.encrypt(bytes(text, "UTF-8"), 0)[0]
    encrypted_text = base64.b64encode(encrypted_data).decode()
    print("Exported data:", encrypted_text)

    return encrypted_text


# Function for decryption
def decrypt_file():
    mode = input("Mode (sym / asym): ")
    while mode != "sym" and mode != "asym":
        mode = input("Mode (sym / asym): ")

    if mode == "sym":
        decrypted_text = decrypt_sym()
        if decrypted_text:
            save_file("sym_decrypted.txt", decrypted_text)
            print("Decryption is completed.")
            print("File has been saved as sym_decrypted.txt.")
    else:
        decrypted_text = decrypt_asym()
        if decrypted_text:
            save_file("asym_decrypted.txt", decrypted_text)
            print("Decryption is completed.")
            print("File has been saved as asym_decrypted.txt.")


# Symmetric decryption
def decrypt_sym():
    try:
        file = open("secret_key.txt", "r")
        secret_key_text = file.read()
        file.close()
    except:
        print("Secret key hasn't been created yet.")
        return

    try:
        file = open("sym_encrypted.txt", "r")
        encrypted_text = file.read()
        file.close()
    except:
        print("Encrypted file hasn't been created yet.")
        return

    print("Imported data:", encrypted_text)
    secret_key = base64.b64decode(secret_key_text.encode())
    imported_data = base64.b64decode(encrypted_text)
    iv = imported_data[:16]
    cipher = AES.new(secret_key, AES.MODE_CFB, iv)
    decrypted_data = cipher.decrypt(imported_data[16:])
    decrypted_text = decrypted_data.decode()
    print("Exported data:", decrypted_text, end="")

    return decrypted_text


# Asymmetric decryption
def decrypt_asym():
    try:
        file = open("private_key.txt", "r")
        private_key_text = file.read()
        file.close()
    except:
        print("Private key hasn't been created yet.")
        return

    try:
        file = open("asym_encrypted.txt", "r")
        encrypted_text = file.read()
        file.close()
    except:
        print("Encrypted file hasn't been created yet.")
        return

    print("Imported data:", encrypted_text)
    private_key = RSA.importKey(private_key_text)
    decrypted_data = private_key.decrypt(base64.b64decode(encrypted_text.encode()))
    decrypted_text = decrypted_data.decode()
    print("Exported data:", decrypted_text, end="")

    return decrypted_text


# Function for calculating hash
def calculate_hash():
    filename = input("Filename: ")

    try:
        file = open(filename, "r")
        data = file.read()
        file.close()
    except:
        print("File not found.")
        return

    file_hash = MD5.new(data.encode()).hexdigest()
    save_file("hash.txt", file_hash)
    print("Hash:", file_hash)
    print("File has been saved as hash.txt.")

    return file_hash


# Function for creating digital signature
def digital_signature():
    try:
        file = open("private_key.txt", "r")
        private_key_text = file.read()
        file.close()
    except:
        print("Private key hasn't been created yet.")
        return

    filename = input("Filename: ")

    try:
        file = open(filename, "r")
        data = file.read()
        file.close()
    except:
        print("File not found.")
        return

    private_key = RSA.importKey(private_key_text)
    digital_signer = PKCS1_PSS.new(private_key)
    digital_signature_data = digital_signer.sign(MD5.new(data.encode()))
    print("Digital signature successfully created.")

    digital_signature_text = base64.b64encode(digital_signature_data).decode()
    save_file("digital_signature.txt", digital_signature_text)
    print("File has been saved as digital_signature.txt.")


# Function for digital signature verification
def digital_signature_verification():
    try:
        file = open("public_key.txt", "r")
        public_key_text = file.read()
        file.close()
    except:
        print("Public key hasn't been created yet.")
        return

    filename = input("Filename: ")
    try:
        file = open(filename, "r")
        data = file.read()
        file.close()
    except:
        print("File not found.")
        return

    try:
        file = open("digital_signature.txt", "r")
        digital_signature_text = file.read()
        file.close()
    except:
        print("Digital signature hasn't been created yet.")
        return

    public_key = RSA.importKey(public_key_text)
    digital_signature_data = base64.b64decode(digital_signature_text)
    digital_signer = PKCS1_PSS.new(public_key)

    if digital_signer.verify(MD5.new(data.encode()), digital_signature_data):
        print("Digital signature is valid.")
    else:
        print("Digital signature is invalid.")


# Function for saving files
def save_file(filename, text):
    file = open(filename, "w")
    file.write(text)
    file.close()


def menu():
    print("Main menu")
    print("---------")
    print("1) Create secret key")
    print("2) Create public and private key")
    print("3) Encrypt file")
    print("4) Decrypt file")
    print("5) Hash")
    print("6) Digital signature")
    print("7) Digital signature verification")
    print("0) Exit")
    print()

    option = int(input("Select option: "))
    print()

    if option == 1:
        print("Create secret key")
        print("-----------------")
        create_secret_key()
    elif option == 2:
        print("Create public and private key")
        print("-----------------------------")
        create_public_private_keys()
    elif option == 3:
        print("Encrypt file")
        print("------------")
        encrypt_file()
    elif option == 4:
        print("Decrypt file")
        print("------------")
        decrypt_file()
    elif option == 5:
        print("Hash")
        print("----")
        calculate_hash()
    elif option == 6:
        print("Digital signature")
        print("-----------------")
        digital_signature()
    elif option == 7:
        print("Digital signature verification")
        print("------------------------------")
        digital_signature_verification()
    elif option == 0:
        print("The end :)")
    else:
        print("You've entered a wrong number.")

    return option


def main():
    while menu():
        print()

if __name__ == "__main__":
    main()

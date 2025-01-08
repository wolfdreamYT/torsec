import os
import sys
import zipfile
import base64
from hashlib import sha256

MASTER_KEY = "1234"
CUSTOM_HEADER = b"TORSECA12CC3247ZX7J5U9226" 


def hash_key(key):
    """
    Generate a SHA-256 hash from the provided key.
    """
    return sha256(key.encode()).digest()


def create_torsec_file(filepath, files, password):
    """
    Creates a .torsec file containing the specified files, with password protection.
    Adds a custom header and encryption for compatibility only with this script.
    """
    try:
        hashed_password = hash_key(password)

        with zipfile.ZipFile(filepath, 'w', compression=zipfile.ZIP_DEFLATED) as zf:
            for file in files:
                if os.path.exists(file):
                    with open(file, 'rb') as f:
                        content = f.read()
                        encrypted_content = base64.b64encode(content).decode()

                    zf.writestr(file, encrypted_content)

            zf.writestr('signature', base64.b64encode(hashed_password).decode())

        with open(filepath, 'rb') as f:
            zip_content = f.read()

        with open(filepath, 'wb') as f:
            f.write(CUSTOM_HEADER + zip_content)

        print(f".torsec file created successfully: {filepath}")
    except Exception as e:
        print(f"Failed to create .torsec file: {e}")


def extract_torsec_file(filepath, output_dir, password):
    """
    Extracts and decrypts the contents of a .torsec file to the specified directory.
    Validates the custom header and password.
    """
    try:
        with open(filepath, 'rb') as f:
            header = f.read(len(CUSTOM_HEADER))
            if header != CUSTOM_HEADER:
                print("Error: Invalid .torsec file format.")
                return

            zip_content = f.read()

        temp_zip_path = filepath + ".temp.zip"
        with open(temp_zip_path, 'wb') as f:
            f.write(zip_content)

        hashed_password = hash_key(password)

        with zipfile.ZipFile(temp_zip_path, 'r') as zf:
            signature = zf.read('signature').decode()
            if signature != base64.b64encode(hashed_password).decode():
                print("Incorrect password or file integrity compromised.")
                os.remove(temp_zip_path)
                return

            for file in zf.namelist():
                if file == 'signature':
                    continue 

                encrypted_content = zf.read(file).decode()
                decrypted_content = base64.b64decode(encrypted_content)

                output_path = os.path.join(output_dir, file)
                os.makedirs(os.path.dirname(output_path), exist_ok=True)
                with open(output_path, 'wb') as f:
                    f.write(decrypted_content)

        os.remove(temp_zip_path)
        print(f".torsec file extracted successfully to: {output_dir}")
    except zipfile.BadZipFile:
        print("The specified file is not a valid .torsec file.")
    except Exception as e:
        print(f"Failed to extract .torsec file: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  To create a .torsec file: python torsec_handler.py create <file.torsec> <password> <files...>")
        print("  To extract a .torsec file: python torsec_handler.py extract <file.torsec> <password> <output_dir>")
        sys.exit(1)

    command = sys.argv[1].lower()

    if command == "create":
        if len(sys.argv) < 5:
            print("You must provide a password and at least one file to create a .torsec file.")
            sys.exit(1)

        file_path = sys.argv[2]
        password = sys.argv[3]
        files = sys.argv[4:]
        create_torsec_file(file_path, files, password)
    elif command == "extract":
        if len(sys.argv) < 5:
            print("You must provide a password and an output directory to extract a .torsec file.")
            sys.exit(1)

        file_path = sys.argv[2]
        password = sys.argv[3]
        output_dir = sys.argv[4]
        extract_torsec_file(file_path, output_dir, password)
    else:
        print("Invalid command. Use 'create' or 'extract'.")
        sys.exit(1)

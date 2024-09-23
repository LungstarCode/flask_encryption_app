from flask import Flask, render_template, request, send_file, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import os
import hashlib

app = Flask(__name__)

# Directories for file handling
UPLOAD_FOLDER = 'uploads'
DOWNLOAD_FOLDER = 'downloads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(DOWNLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/encrypt_text_form', methods=['GET'])
def encrypt_text_form():
    return render_template('encrypt_text.html')

@app.route('/decrypt_text_form', methods=['GET'])
def decrypt_text_form():
    return render_template('decrypt_text.html')


# Function to generate a key from a password
def generate_key_from_password(password):
    return hashlib.sha256(password.encode()).digest()  # AES key size is 256 bits


# Function to pad the text to make its length a multiple of the block size
def pad(text, block_size):
    padding_length = block_size - len(text) % block_size
    padding = chr(padding_length) * padding_length
    return text + padding

# Function to unpad the decrypted text
def unpad(text):
    padding_length = ord(text[-1])
    return text[:-padding_length]

# AES encryption function
def aes_encrypt(plaintext, key):
    iv = os.urandom(16)  # Initialization vector
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Convert plaintext (string) to bytes
    plaintext_bytes = pad(plaintext, algorithms.AES.block_size).encode('utf-8')

    ciphertext = encryptor.update(plaintext_bytes) + encryptor.finalize()
    return iv + ciphertext

# AES decryption function
def aes_decrypt(ciphertext, key):
    iv = ciphertext[:16]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt and unpad the plaintext
    decrypted_bytes = decryptor.update(ciphertext[16:]) + decryptor.finalize()
    return unpad(decrypted_bytes.decode('utf-8'))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return 'No file part'
    
    file = request.files['file']
    if file.filename == '':
        return 'No selected file'
    
    if file:
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        return redirect(url_for('encrypt_file', filename=filename))

@app.route('/encrypt/<filename>', methods=['GET', 'POST'])
def encrypt_file(filename):
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)

    with open(filepath, 'r') as file:
        plaintext = file.read()

    password = "your_default_password"  # This should be replaced or managed securely
    key = generate_key_from_password(password)
    encrypted_data = aes_encrypt(plaintext, key)

    encrypted_filename = f"encrypted_{filename}"
    encrypted_filepath = os.path.join(DOWNLOAD_FOLDER, encrypted_filename)

    with open(encrypted_filepath, 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    # Save the key for decryption later
    key_filename = f"key_{filename}.bin"
    with open(os.path.join(DOWNLOAD_FOLDER, key_filename), 'wb') as key_file:
        key_file.write(key)

    return f'''
    <h3>File encrypted successfully!</h3>
    <p>Download the <a href="/download/{encrypted_filename}">Encrypted File</a></p>
    <p>Download the <a href="/download/{key_filename}">Key File</a> (save it for decryption)</p>
    <br>
    <a href="/">Go back</a>
    '''


@app.route('/download/<filename>')
def download_file(filename):
    return send_file(os.path.join(DOWNLOAD_FOLDER, filename), as_attachment=True)

@app.route('/decrypt', methods=['POST'])
def decrypt_file():
    if 'encrypted_file' not in request.files or 'key_file' not in request.files:
        return 'Both encrypted file and key file are required'
    
    encrypted_file = request.files['encrypted_file']
    key_file = request.files['key_file']

    encrypted_filename = secure_filename(encrypted_file.filename)
    encrypted_filepath = os.path.join(UPLOAD_FOLDER, encrypted_filename)
    encrypted_file.save(encrypted_filepath)

    key_filename = secure_filename(key_file.filename)
    key_filepath = os.path.join(UPLOAD_FOLDER, key_filename)
    key_file.save(key_filepath)

    with open(encrypted_filepath, 'rb') as enc_file:
        encrypted_data = enc_file.read()
    
    with open(key_filepath, 'rb') as key_file:
        key = key_file.read()

    decrypted_text = aes_decrypt(encrypted_data, key)

    decrypted_filename = f"decrypted_{encrypted_filename}"
    decrypted_filepath = os.path.join(DOWNLOAD_FOLDER, decrypted_filename)

    with open(decrypted_filepath, 'w') as decrypted_file:
        decrypted_file.write(decrypted_text)

    return f'''
    <h3>File decrypted successfully!</h3>
    <p>Download the <a href="/download/{decrypted_filename}">Decrypted File</a></p>
    <br>
    <a href="/">Go back</a>
    '''

# New route to handle text and password encryption
@app.route('/encrypt_text', methods=['POST'])
def encrypt_text():
    plaintext = request.form['plaintext']
    password = request.form['password']
    
    key = generate_key_from_password(password)
    encrypted_data = aes_encrypt(plaintext, key)

    # Convert the ciphertext to a displayable format (e.g., base64)
    encrypted_hex = encrypted_data.hex()

    return f'''
    <h3>Text encrypted successfully!</h3>
    <p>Encrypted text (in hex): {encrypted_hex}</p>
    <br>
    <a href="/">Go back</a>
    '''

@app.route('/decrypt_text', methods=['POST'])
def decrypt_text():
    ciphertext_hex = request.form['ciphertext']
    password = request.form['password']
    
    # Convert the hex string back to bytes
    ciphertext = bytes.fromhex(ciphertext_hex)
    key = generate_key_from_password(password)

    try:
        decrypted_text = aes_decrypt(ciphertext, key)
        return f'''
        <h3>Text decrypted successfully!</h3>
        <p>Decrypted text: {decrypted_text}</p>
        <br>
        <a href="/">Go back</a>
        '''
    except Exception as e:
        return f'''
        <h3>Decryption failed!</h3>
        <p>Error: {str(e)}</p>
        <br>
        <a href="/">Go back</a>
        '''

if __name__ == '__main__':
    app.run(debug=True , port = 2000)

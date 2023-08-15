from flask import Flask, request, jsonify
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet

import base64

app = Flask(__name__)


import os



# def generate_iv():
#     return os.urandom(16)

# def generate_encryption_key():
#     return Fernet.generate_key()[:32]

# iv = generate_iv().hex()[:16]   // gen 16 bytes of Intial vector
# key=generate_encryption_key()  // gen 32 bytes of encryption key
# print(iv, key)
 
# Replace these keys and IV with your own secret keys and IV
ENCRYPTION_KEY = b'QHHEQe2VqnoepTsf5E8LzRuLp3YdWFOB'
IV = b'e092b7484e48aa1d'



def encrypt_data(data, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data.encode('utf-8')) + encryptor.finalize()
    return encrypted_data

def decrypt_data(encrypted_data, key, iv):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=backend)
    decryptor = cipher.decryptor()
    decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
    return decrypted_data.decode('utf-8')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json.get('data')
    encrypted_data = encrypt_data(data, ENCRYPTION_KEY, IV)
    return jsonify({'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8')})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    encrypted_data = base64.b64decode(request.json.get('encrypted_data'))
    decrypted_data = decrypt_data(encrypted_data, ENCRYPTION_KEY, IV)
    return jsonify({'decrypted_data': decrypted_data})

if __name__ == '__main__':
    app.run(debug=True)
